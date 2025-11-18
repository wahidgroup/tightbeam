//! Common traits for handshake orchestrators.
//!
//! Provides shared functionality across CMS and ECIES client/server implementations:
//! - Profile negotiation (server-side)
//! - AEAD session key finalization (all orchestrators)
//! - Alert attribute processing (all orchestrators)

use crate::constants::{MIN_SALT_ENTROPY_BYTES, TIGHTBEAM_SESSION_KDF_INFO};
use crate::crypto::aead::KeyInit;
use crate::crypto::kdf::KdfFunction;
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::crypto::x509::attr::{Attribute, Attributes};
use crate::oids::HANDSHAKE_ABORT_ALERT;
use crate::transport::handshake::attributes::{extract_alert_x509, find_x509};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{select_profile, SecurityOffer};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Provides profile negotiation logic for server-side handshake orchestrators.
///
/// Servers must implement `supported_profiles()` to expose their configured
/// security profiles. The trait provides default negotiation logic handling
/// both client-offered and dealer's choice modes.
///
/// # Usage
/// - **Negotiation mode**: Client sends `SecurityOffer`, server selects first mutual profile
/// - **Dealer's choice mode**: Client sends no offer, server uses first configured profile
pub trait HandshakeNegotiation {
	/// Get the list of supported security profiles.
	fn supported_profiles(&self) -> &[SecurityProfileDesc];

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
	/// - `NegotiationError`: No mutually supported profile found
	fn negotiate_profile(&self, offer: Option<&SecurityOffer>) -> Result<SecurityProfileDesc, HandshakeError> {
		let supported = self.supported_profiles();
		if supported.is_empty() {
			return Err(HandshakeError::NoSupportedProfiles);
		}

		match offer {
			Some(offer) => Ok(select_profile(offer, supported)?),
			None => Ok(supported[0]), // Dealer's choice
		}
	}
}

/// Provides session key finalization logic for all handshake orchestrators.
///
/// Orchestrators must implement `selected_profile()` to expose the negotiated
/// security profile. The trait provides default HKDF-based key derivation with
/// entropy validation.
///
/// # Security Properties
/// - Enforces minimum `MIN_SALT_ENTROPY_BYTES` salt entropy
/// - Uses HKDF with `TIGHTBEAM_SESSION_KDF_INFO` domain separation
/// - Derives key size dynamically from negotiated AEAD cipher profile
/// - Constant-time operations via underlying crypto primitives
pub trait HandshakeFinalization<P>
where
	P: CryptoProvider,
{
	/// Get the selected/negotiated security profile.
	fn selected_profile(&self) -> Option<SecurityProfileDesc>;

	/// Derive the final session AEAD cipher from input key material.
	///
	/// # Parameters
	/// - `input_key`: Base key material (CEK for CMS, base session key for ECIES)
	/// - `salt`: Context-specific salt:
	///   - **CMS**: transcript hash (32 bytes)
	///   - **ECIES**: client_random || server_random (64 bytes)
	///
	/// # Returns
	/// Initialized AEAD cipher ready for encryption/decryption
	///
	/// # Errors
	/// - `InvalidState`: No profile selected or profile missing AEAD key size
	/// - `InsufficientSaltEntropy`: Salt shorter than `MIN_SALT_ENTROPY_BYTES`
	/// - `KeyDerivationFailed`: HKDF or cipher initialization failed
	fn derive_session_aead(&self, input_key: &[u8], salt: &[u8]) -> Result<P::AeadCipher, HandshakeError>
	where
		P::AeadCipher: KeyInit,
	{
		let profile = self.selected_profile().ok_or(HandshakeError::InvalidState)?;
		let key_size = profile.aead_key_size.ok_or(HandshakeError::InvalidState)? as usize;

		// Enforce minimum salt entropy for both protocols
		if salt.len() < MIN_SALT_ENTROPY_BYTES {
			return Err(HandshakeError::InsufficientSaltEntropy {
				actual: salt.len(),
				minimum: MIN_SALT_ENTROPY_BYTES,
			});
		}

		let final_key_bytes = P::Kdf::derive_dynamic_key(input_key, TIGHTBEAM_SESSION_KDF_INFO, Some(salt), key_size)?;
		Ok(P::AeadCipher::new_from_slice(&final_key_bytes[..])?)
	}
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
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::der::asn1::ObjectIdentifier;
	use crate::oids::{AES_128_GCM, AES_256_GCM, CURVE_SECP256K1, HASH_SHA256, SIGNER_ECDSA_WITH_SHA256};

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
			digest: HASH_SHA256,
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
	fn test_negotiate_profile_with_offer() -> Result<(), Box<dyn std::error::Error>> {
		let p_a = create_test_profile(AES_128_GCM, 16);
		let p_b = create_test_profile(AES_256_GCM, 32);

		let server = MockServer { profiles: vec![p_a, p_b] };

		let offer = SecurityOffer::new(vec![p_a, p_b]);
		let selected = server.negotiate_profile(Some(&offer))?;
		assert_eq!(selected.aead_key_size, Some(16)); // Should select p_a (client's first preference)
		Ok(())
	}

	#[test]
	fn test_negotiate_profile_dealers_choice() -> Result<(), Box<dyn std::error::Error>> {
		let p_a = create_test_profile(AES_128_GCM, 16);
		let p_b = create_test_profile(AES_256_GCM, 32);

		let server = MockServer { profiles: vec![p_a, p_b] };

		let selected = server.negotiate_profile(None)?;
		assert_eq!(selected.aead_key_size, Some(16)); // Should select first (p_a)
		Ok(())
	}

	#[test]
	fn test_negotiate_profile_no_supported() {
		let server = MockServer { profiles: vec![] };

		let result = server.negotiate_profile(None);
		assert!(matches!(result, Err(HandshakeError::NoSupportedProfiles)));
	}

	#[test]
	fn test_derive_session_aead_success() {
		let profile = create_test_profile(AES_256_GCM, 32);
		let client = MockClient { profile: Some(profile) };

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];

		let result = <MockClient as HandshakeFinalization<DefaultCryptoProvider>>::derive_session_aead(
			&client, &input_key, &salt,
		);
		assert!(result.is_ok());
	}

	#[test]
	fn test_derive_session_aead_insufficient_salt() {
		let profile = create_test_profile(AES_256_GCM, 32);
		let client = MockClient { profile: Some(profile) };

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 8]; // Only 8 bytes

		let result = <MockClient as HandshakeFinalization<DefaultCryptoProvider>>::derive_session_aead(
			&client, &input_key, &salt,
		);
		assert!(matches!(
			result,
			Err(HandshakeError::InsufficientSaltEntropy { actual: 8, minimum: 16 })
		));
	}

	#[test]
	fn test_derive_session_aead_no_profile() {
		let client = MockClient { profile: None };

		let input_key = [0x42u8; 32];
		let salt = [0x99u8; 32];

		let result = <MockClient as HandshakeFinalization<DefaultCryptoProvider>>::derive_session_aead(
			&client, &input_key, &salt,
		);
		assert!(matches!(result, Err(HandshakeError::InvalidState)));
	}
}
