//! Common traits for handshake orchestrators.
//!
//! Provides shared functionality across CMS and ECIES client/server implementations:
//! - Profile negotiation (server-side)
//! - AEAD session key finalization (all orchestrators)
//! - Alert attribute processing (all orchestrators)

use crate::constants::{MIN_SALT_ENTROPY_BYTES, TIGHTBEAM_C2S_KDF_INFO, TIGHTBEAM_S2C_KDF_INFO};
use crate::crypto::aead::KeyInit;
use crate::crypto::kdf::KdfFunction;
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::crypto::x509::attr::{Attribute, Attributes};
use crate::der::asn1::ObjectIdentifier;
use crate::oids::HANDSHAKE_ABORT_ALERT;
use crate::oids::{AES_128_GCM, AES_256_GCM};
use crate::transport::handshake::attributes::{extract_alert_x509, find_x509};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	select_profile, DefaultStrengthFloor, NegotiationError, ProfileStrengthPolicy, SecurityOffer,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Provides profile negotiation logic for server-side handshake orchestrators.
///
/// Servers must implement `supported_profiles()` to expose their configured
/// security profiles. The trait provides default negotiation logic handling
/// both client-offered and dealer's choice modes.
///
/// # Usage
/// - **Negotiation mode**: Client sends `SecurityOffer`, server selects the first mutual
///   profile in *server* preference order
/// - **Dealer's choice mode**: Client sends no offer, server uses its first configured
///   profile that meets the strength policy
///
/// # Security
/// Both modes filter profiles through [`ProfileStrengthPolicy`] before selection,
/// so a weak profile left in `supported_profiles()` for compatibility cannot be
/// negotiated (CWE-757 downgrade resistance).
pub trait HandshakeNegotiation {
	/// Get the list of supported security profiles (first = most preferred).
	fn supported_profiles(&self) -> &[SecurityProfileDesc];

	/// Minimum-strength policy applied before selection.
	///
	/// Defaults to [`DefaultStrengthFloor`] (256-bit AEAD key, >= 256-bit digest).
	fn strength_policy(&self) -> &dyn ProfileStrengthPolicy {
		&DefaultStrengthFloor
	}

	/// Negotiate a security profile with the peer.
	///
	/// # Parameters
	/// - `offer`: Client's `SecurityOffer` (None for dealer's choice mode)
	///
	/// # Returns
	/// The selected `SecurityProfileDesc`
	///
	/// # Errors
	/// - `NoSupportedProfiles`: No profiles configured on server
	/// - `NegotiationError(BelowStrengthFloor)`: No configured profile meets the policy
	/// - `NegotiationError`: No mutually supported profile found
	fn negotiate_profile(&self, offer: Option<&SecurityOffer>) -> Result<SecurityProfileDesc, HandshakeError> {
		let supported = self.supported_profiles();
		if supported.is_empty() {
			return Err(HandshakeError::NoSupportedProfiles);
		}

		let policy = self.strength_policy();
		let eligible: Vec<SecurityProfileDesc> = supported
			.iter()
			.filter(|profile| policy.meets_floor(profile))
			.copied()
			.collect();
		if eligible.is_empty() {
			return Err(NegotiationError::BelowStrengthFloor.into());
		}

		match offer {
			Some(offer) => Ok(select_profile(offer, &eligible)?),
			None => Ok(eligible[0]), // Dealer's choice
		}
	}
}

/// Map a negotiated AEAD OID to its key byte length.
///
/// The peer-declared `aead_key_size` is advisory input. The
/// negotiated OID is the authoritative binding (CWE-345).
fn aead_key_size_from_oid(oid: ObjectIdentifier) -> Result<usize, HandshakeError> {
	if oid == AES_128_GCM {
		Ok(16)
	} else if oid == AES_256_GCM {
		Ok(32)
	} else {
		Err(HandshakeError::UnsupportedAeadAlgorithm)
	}
}

/// Directional session ciphers derived at handshake completion.
///
/// Field names use the canonical client-to-server and server-to-client
/// directions. Role mapping into send and receive sides happens in
/// [`crate::crypto::aead::SessionKeys`].
pub struct DirectionalCiphers<C> {
	/// Cipher for the client-to-server direction.
	pub client_to_server: C,
	/// Cipher for the server-to-client direction.
	pub server_to_client: C,
}

/// Provides session key finalization logic for all handshake orchestrators.
///
/// Orchestrators must implement `selected_profile()` to expose the negotiated
/// security profile. The trait provides default HKDF-based key derivation with
/// entropy validation.
///
/// # Security Properties
/// - Enforces minimum `MIN_SALT_ENTROPY_BYTES` salt entropy
/// - Uses HKDF with per-direction domain separation (`TIGHTBEAM_C2S_KDF_INFO`,
///   `TIGHTBEAM_S2C_KDF_INFO`), the RFC 5869 info-label pattern behind the
///   TLS 1.3 directional traffic secrets (RFC 8446, § 7.3)
/// - Derives key size dynamically from negotiated AEAD cipher profile
/// - Constant-time operations via underlying crypto primitives
pub trait HandshakeFinalization<P>
where
	P: CryptoProvider,
{
	/// Get the selected/negotiated security profile.
	fn selected_profile(&self) -> Option<SecurityProfileDesc>;

	/// Derive the directional session AEAD ciphers from input key material.
	///
	/// # Parameters
	/// - `input_key`: Base key material (CEK for CMS, base session key for ECIES)
	/// - `salt`: Context-specific salt:
	///   - **CMS**: transcript hash (32 bytes)
	///   - **ECIES**: client_random || server_random (64 bytes)
	///
	/// # Returns
	/// Initialized client-to-server and server-to-client AEAD ciphers
	///
	/// # Errors
	/// - `InvalidState`: No profile selected or profile missing AEAD OID/key size
	/// - `UnsupportedAeadAlgorithm`: Negotiated AEAD OID has no known key size
	/// - `AeadKeySizeMismatch`: Peer-declared key size disagrees with the OID
	/// - `InsufficientSaltEntropy`: Salt shorter than `MIN_SALT_ENTROPY_BYTES`
	/// - `KeyDerivationFailed`: HKDF or cipher initialization failed
	fn derive_directional_aead(
		&self,
		input_key: &[u8],
		salt: &[u8],
	) -> Result<DirectionalCiphers<P::AeadCipher>, HandshakeError>
	where
		P::AeadCipher: KeyInit,
	{
		let profile = self.selected_profile().ok_or(HandshakeError::InvalidState)?;
		let aead_oid = profile.aead.ok_or(HandshakeError::InvalidState)?;
		let key_size = usize::from(profile.aead_key_size.ok_or(HandshakeError::InvalidState)?);

		// CWE-345: the negotiated OID is authoritative for the HKDF output length.
		let expected = aead_key_size_from_oid(aead_oid)?;
		if key_size != expected {
			return Err(HandshakeError::AeadKeySizeMismatch { declared: key_size, expected });
		}

		// Enforce minimum salt entropy for both protocols
		if salt.len() < MIN_SALT_ENTROPY_BYTES {
			return Err(HandshakeError::InsufficientSaltEntropy {
				actual: salt.len(),
				minimum: MIN_SALT_ENTROPY_BYTES,
			});
		}

		let client_to_server = derive_labeled_cipher::<P>(input_key, salt, TIGHTBEAM_C2S_KDF_INFO, key_size)?;
		let server_to_client = derive_labeled_cipher::<P>(input_key, salt, TIGHTBEAM_S2C_KDF_INFO, key_size)?;
		Ok(DirectionalCiphers { client_to_server, server_to_client })
	}
}

/// Derive one direction's cipher under the given KDF info label.
fn derive_labeled_cipher<P>(
	input_key: &[u8],
	salt: &[u8],
	info: &[u8],
	key_size: usize,
) -> Result<P::AeadCipher, HandshakeError>
where
	P: CryptoProvider,
	P::AeadCipher: KeyInit,
{
	let key_bytes = P::Kdf::derive_dynamic_key(input_key, info, Some(salt), key_size)?;
	let cipher = P::AeadCipher::new_from_slice(&key_bytes[..])?;
	Ok(cipher)
}

/// Provides alert attribute processing for all handshake orchestrators.
///
/// All orchestrators automatically implement this trait via blanket impl.
/// Call `check_for_alert()` early in message processing to detect peer-sent
/// abort alerts.
///
/// # Alert Types
/// - `AuthRequired`: Peer requires mutual authentication
/// - `VersionMismatch`: Protocol version incompatible
/// - `AlgorithmMismatch`: No mutual cryptographic algorithms
/// - `DecryptFail`: Decryption or signature verification failed
/// - `FinishedIntegrityFail`: Transcript hash mismatch
pub trait HandshakeAlertHandler {
	/// Check for abort alert in unprotected attributes.
	///
	/// # Security
	/// Abort alerts exist in *unprotected* attributes and are therefore
	/// advisory and unauthenticated (as in TLS): a MITM can inject a spurious
	/// abort (DoS) or suppress a real one.
	///
	/// # Parameters
	/// - `attrs`: Optional X.509 attributes from CMS unprotected attributes
	///
	/// # Returns
	/// - `Ok(())`: No alert present, safe to proceed
	/// - `Err(HandshakeError::AbortReceived(alert))`: Peer sent abort, handshake terminated
	///
	/// # Errors
	/// - `AbortReceived`: Alert detected with specific alert code
	/// - `InvalidAttributeArity`: Alert attribute malformed
	/// - `InvalidIntegerEncoding`: Alert code not valid INTEGER
	fn check_for_alert(&self, attrs: Option<&Attributes>) -> Result<(), HandshakeError> {
		if let Some(attrs) = attrs {
			// Convert to slice of references to avoid cloning
			let attr_refs: Vec<&Attribute> = attrs.iter().collect();

			// Check for abort alert attribute
			if let Ok(alert_attr) = find_x509(&attr_refs, &HANDSHAKE_ABORT_ALERT) {
				let alert = extract_alert_x509(alert_attr)?;
				return Err(HandshakeError::AbortReceived(alert));
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::{AeadProvider, DefaultCryptoProvider};
	use crate::der::asn1::ObjectIdentifier;
	use crate::oids::{AES_128_GCM, AES_256_GCM, CURVE_SECP256K1, HASH_SHA256, SIGNER_ECDSA_WITH_SHA256};
	use crate::transport::handshake::negotiation::NegotiationError;
	use std::error::Error;

	// Mock struct for testing negotiation
	struct MockServer {
		profiles: Vec<SecurityProfileDesc>,
	}

	impl HandshakeNegotiation for MockServer {
		fn supported_profiles(&self) -> &[SecurityProfileDesc] {
			&self.profiles
		}
	}

	// Mock struct for testing finalization
	struct MockClient {
		profile: Option<SecurityProfileDesc>,
	}

	impl<P> HandshakeFinalization<P> for MockClient
	where
		P: CryptoProvider,
	{
		fn selected_profile(&self) -> Option<SecurityProfileDesc> {
			self.profile
		}
	}

	fn create_test_profile(aead_oid: ObjectIdentifier, key_size: u16) -> SecurityProfileDesc {
		SecurityProfileDesc {
			digest: Some(HASH_SHA256),
			aead: Some(aead_oid),
			aead_key_size: Some(key_size),
			signature: Some(SIGNER_ECDSA_WITH_SHA256),
			kdf: Some(HASH_SHA256),
			curve: Some(CURVE_SECP256K1),
			key_wrap: None,
			kem: None,
		}
	}

	#[test]
	fn test_negotiate_profile_with_offer_enforces_floor() -> Result<(), Box<dyn Error>> {
		let p_a = create_test_profile(AES_128_GCM, 16);
		let p_b = create_test_profile(AES_256_GCM, 32);

		let server = MockServer { profiles: vec![p_a, p_b] };

		// 128-bit AEAD fails the default strength floor; only p_b survives.
		let offer = SecurityOffer::new(vec![p_a, p_b]);
		let selected = server.negotiate_profile(Some(&offer))?;
		assert_eq!(selected.aead_key_size, Some(32));
		Ok(())
	}

	#[test]
	fn test_negotiate_profile_dealers_choice_skips_below_floor() -> Result<(), Box<dyn Error>> {
		let p_a = create_test_profile(AES_128_GCM, 16);
		let p_b = create_test_profile(AES_256_GCM, 32);

		let server = MockServer { profiles: vec![p_a, p_b] };

		let selected = server.negotiate_profile(None)?;
		assert_eq!(selected.aead_key_size, Some(32));
		Ok(())
	}

	#[test]
	fn test_negotiate_profile_all_below_floor() {
		let p_a = create_test_profile(AES_128_GCM, 16);

		let server = MockServer { profiles: vec![p_a] };

		let offer = SecurityOffer::new(vec![p_a]);
		let result = server.negotiate_profile(Some(&offer));
		assert!(matches!(
			result,
			Err(HandshakeError::NegotiationError(NegotiationError::BelowStrengthFloor))
		));
	}

	#[test]
	fn test_negotiate_profile_no_supported() {
		let server = MockServer { profiles: vec![] };

		let result = server.negotiate_profile(None);
		assert!(matches!(result, Err(HandshakeError::NoSupportedProfiles)));
	}

	fn derive_directional(
		client: &MockClient,
		input_key: &[u8],
		salt: &[u8],
	) -> Result<DirectionalCiphers<<DefaultCryptoProvider as AeadProvider>::AeadCipher>, HandshakeError> {
		<MockClient as HandshakeFinalization<DefaultCryptoProvider>>::derive_directional_aead(client, input_key, salt)
	}

	#[test]
	fn test_derive_directional_aead_success() {
		let profile = create_test_profile(AES_256_GCM, 32);
		let client = MockClient { profile: Some(profile) };

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];

		let result = derive_directional(&client, &input_key, &salt);
		assert!(result.is_ok());
	}

	#[test]
	fn test_derive_directional_aead_directions_differ() {
		use crate::crypto::aead::Aead;

		let profile = create_test_profile(AES_256_GCM, 32);
		let client = MockClient { profile: Some(profile) };

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];

		let ciphers = derive_directional(&client, &input_key, &salt).unwrap();

		// Same nonce and plaintext under both directions must produce
		// different ciphertexts, proving the info labels separate the keys.
		let nonce = [0u8; 12];
		let plaintext = b"directional key separation";
		let c2s_ciphertext = ciphers.client_to_server.encrypt((&nonce).into(), plaintext.as_slice()).unwrap();
		let s2c_ciphertext = ciphers.server_to_client.encrypt((&nonce).into(), plaintext.as_slice()).unwrap();
		assert_ne!(c2s_ciphertext, s2c_ciphertext);
	}

	#[test]
	fn test_derive_directional_aead_is_deterministic() {
		use crate::crypto::aead::Aead;

		let profile = create_test_profile(AES_256_GCM, 32);
		let client = MockClient { profile: Some(profile) };

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];

		let first = derive_directional(&client, &input_key, &salt).unwrap();
		let second = derive_directional(&client, &input_key, &salt).unwrap();

		// Both derivations agree, so two independent endpoints derive the
		// same directional keys from shared input material.
		let nonce = [0u8; 12];
		let plaintext = b"deterministic derivation";
		let first_ciphertext = first.client_to_server.encrypt((&nonce).into(), plaintext.as_slice()).unwrap();
		let second_ciphertext = second.client_to_server.encrypt((&nonce).into(), plaintext.as_slice()).unwrap();
		assert_eq!(first_ciphertext, second_ciphertext);
	}

	#[test]
	fn test_derive_directional_aead_insufficient_salt() {
		let profile = create_test_profile(AES_256_GCM, 32);
		let client = MockClient { profile: Some(profile) };

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 8]; // Only 8 bytes

		let result = derive_directional(&client, &input_key, &salt);
		assert!(matches!(
			result,
			Err(HandshakeError::InsufficientSaltEntropy { actual: 8, minimum: 16 })
		));
	}

	#[test]
	fn test_derive_directional_aead_rejects_key_size_oid_mismatch() {
		// Peer declares 16 bytes against an AES-256-GCM OID (CWE-345).
		let profile = create_test_profile(AES_256_GCM, 16);
		let client = MockClient { profile: Some(profile) };

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];

		let result = derive_directional(&client, &input_key, &salt);
		assert!(matches!(
			result,
			Err(HandshakeError::AeadKeySizeMismatch { declared: 16, expected: 32 })
		));
	}

	#[test]
	fn test_derive_directional_aead_rejects_unknown_aead_oid() {
		// A digest OID is not an AEAD algorithm; no key size can be bound.
		let profile = create_test_profile(HASH_SHA256, 32);
		let client = MockClient { profile: Some(profile) };

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];

		let result = derive_directional(&client, &input_key, &salt);
		assert!(matches!(result, Err(HandshakeError::UnsupportedAeadAlgorithm)));
	}

	#[test]
	fn test_derive_directional_aead_no_profile() {
		let client = MockClient { profile: None };

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];

		let result = derive_directional(&client, &input_key, &salt);
		assert!(matches!(result, Err(HandshakeError::InvalidState)));
	}
}
