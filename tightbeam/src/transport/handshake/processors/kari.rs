//! KeyAgreeRecipientInfo recipient processor for TightBeam CMS handshake.
//!
//! Processes received KARI structures to extract the content-encryption key (CEK).

use crate::cms::enveloped_data::{KeyAgreeRecipientInfo, OriginatorIdentifierOrKey, RecipientInfo};
use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, FieldBytesSize, PublicKey, SecretKey};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::kari::kari_unwrap;

/// Recipient-side processor for `KeyAgreeRecipientInfo`.
///
/// This processes a received KARI to extract the content-encryption key (CEK):
/// 1. Extract originator's public key from KARI
/// 2. Perform ECDH with recipient's private key
/// 3. Derive KEK using same KDF and UKM
/// 4. Unwrap encrypted key to get CEK
///
/// Generic over `P: CryptoProvider` which defines the complete cryptographic suite.
pub struct TightBeamKariRecipient<P>
where
	P: CryptoProvider,
{
	/// Recipient's private key for ECDH
	recipient_priv: SecretKey<P::Curve>,
	/// HKDF info string (must match sender's)
	kdf_info: &'static [u8],
	/// Cryptographic provider
	provider: P,
}

impl<P> TightBeamKariRecipient<P>
where
	P: CryptoProvider,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	FieldBytesSize<P::Curve>: ModulusSize,
{
	/// Create a new KARI recipient processor.
	///
	/// Uses default TightBeam KDF info string (`TIGHTBEAM_KARI_KDF_INFO`).
	///
	/// # Parameters
	/// - `provider`: The cryptographic provider defining the security profile
	/// - `recipient_priv`: Recipient's private key for ECDH
	pub fn new(provider: P, recipient_priv: SecretKey<P::Curve>) -> Self {
		Self::with_kdf_info(provider, recipient_priv, TIGHTBEAM_KARI_KDF_INFO)
	}

	/// Create a new KARI recipient processor with custom KDF info.
	///
	/// This allows interoperability with senders using different KDF parameters
	/// while maintaining the provider's KDF algorithm.
	///
	/// # Parameters
	/// - `provider`: The cryptographic provider defining the security profile
	/// - `recipient_priv`: Recipient's private key for ECDH
	/// - `kdf_info`: Info string for HKDF (must match sender's)
	///
	/// # Example
	/// ```ignore
	/// let processor = TightBeamKariRecipient::with_kdf_info(
	///     provider,
	///     recipient_key,
	///     b"custom-kdf-info-v1"
	/// );
	/// ```
	pub fn with_kdf_info(provider: P, recipient_priv: SecretKey<P::Curve>, kdf_info: &'static [u8]) -> Self {
		Self { recipient_priv, kdf_info, provider }
	}

	/// Process a KeyAgreeRecipientInfo to extract the CEK.
	///
	/// # Parameters
	/// - `kari`: The received KeyAgreeRecipientInfo structure
	/// - `recipient_index`: Index of the recipient in recipient_enc_keys (usually 0)
	///
	/// # Returns
	/// The unwrapped content-encryption key (CEK)
	pub fn process_kari(
		&self,
		kari: &KeyAgreeRecipientInfo,
		recipient_index: usize,
	) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validate recipient index
		if recipient_index >= kari.recipient_enc_keys.len() {
			return Err(HandshakeError::InvalidRecipientIndex);
		}

		// 2. Extract originator's public key
		let originator_pub = self.extract_originator_public_key(kari)?;

		// 3-6. Centralized unwrap (ECDH + HKDF + integrity re-wrap)
		let ukm = kari.ukm.as_ref().ok_or(HandshakeError::MissingUkm)?;
		let wrapped_key = kari.recipient_enc_keys[recipient_index].enc_key.as_bytes();
		kari_unwrap(
			&self.provider,
			&self.recipient_priv,
			&originator_pub,
			ukm.as_bytes(),
			self.kdf_info,
			wrapped_key,
		)
	}

	/// Extract originator's public key from KARI.
	fn extract_originator_public_key(
		&self,
		kari: &KeyAgreeRecipientInfo,
	) -> Result<PublicKey<P::Curve>, HandshakeError> {
		match &kari.originator {
			OriginatorIdentifierOrKey::OriginatorKey(orig_key) => {
				// Extract raw public key bytes from BitString
				let pub_key_bytes = orig_key.public_key.raw_bytes();
				Ok(PublicKey::<P::Curve>::from_sec1_bytes(pub_key_bytes)?)
			}
			_ => Err(HandshakeError::UnsupportedOriginatorIdentifier),
		}
	}
}

/// Default implementation for DefaultCryptoProvider.
impl TightBeamKariRecipient<DefaultCryptoProvider> {
	/// Create a recipient processor with default TightBeam settings.
	pub fn with_defaults(recipient_priv: k256::SecretKey) -> Self {
		Self::new(DefaultCryptoProvider::default(), recipient_priv)
	}
}

/// Implement RecipientProcessor trait for TightBeamKariRecipient
impl<P> super::enveloped_data::RecipientProcessor for TightBeamKariRecipient<P>
where
	P: CryptoProvider,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	FieldBytesSize<P::Curve>: ModulusSize,
{
	fn process_recipient(&self, info: &RecipientInfo, recipient_index: usize) -> Result<Vec<u8>, HandshakeError> {
		match info {
			RecipientInfo::Kari(kari) => self.process_kari(kari, recipient_index),
			_ => Err(HandshakeError::UnsupportedOriginatorIdentifier),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	mod recipient {
		use super::*;
		use crate::cms::builder::RecipientInfoBuilder;
		use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, RecipientInfo, UserKeyingMaterial};
		use crate::crypto::sign::ecdsa::k256::SecretKey as K256SecretKey;
		use crate::random::{generate_nonce, OsRng};
		use crate::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
		use crate::transport::handshake::builders::kari::TightBeamKariBuilder;

		#[test]
		fn test_full_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
			// Generate sender and recipient key-pairs
			let sender_key = K256SecretKey::random(&mut OsRng);
			let sender_pubkey = sender_key.public_key();
			let sender_spki = SubjectPublicKeyInfoOwned::from_key(sender_pubkey)?;

			let recipient_key = K256SecretKey::random(&mut OsRng);
			let recipient_pubkey = recipient_key.public_key();

			// Create UKM
			let client_nonce = [0x01u8; 32];
			let server_nonce = [0x02u8; 32];
			let mut ukm_bytes = Vec::new();
			ukm_bytes.extend_from_slice(&client_nonce);
			ukm_bytes.extend_from_slice(&server_nonce);
			let ukm = UserKeyingMaterial::new(ukm_bytes)?;

			// Recipient identifier
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
				issuer: x509_cert::name::Name::default(),
				serial_number: x509_cert::serial_number::SerialNumber::new(&[0x01])?,
			});

			// Key encryption algorithm
			let key_enc_alg = AlgorithmIdentifierOwned { oid: crate::asn1::AES_256_WRAP_OID, parameters: None };

			// Original CEK
			let original_cek = [0x42u8; 32];

			// SENDER SIDE: Build KARI
			let mut builder = TightBeamKariBuilder::default()
				.with_sender_priv(sender_key.clone())
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient_pubkey)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);

			let recipient_info = builder.build(&original_cek).map_err(|e| format!("build failed: {:?}", e))?;

			// Extract KARI from RecipientInfo
			let kari = match recipient_info {
				RecipientInfo::Kari(k) => k,
				_ => panic!("Expected Kari variant"),
			};

			// RECIPIENT SIDE: Process KARI
			let recipient = TightBeamKariRecipient::with_defaults(recipient_key);
			let extracted_cek = recipient.process_kari(&kari, 0)?;

			// Verify: extracted CEK should match original
			assert_eq!(extracted_cek, original_cek);
			Ok(())
		}

		#[test]
		fn test_wrong_key() -> Result<(), Box<dyn std::error::Error>> {
			// Generate sender and two recipient key-pairs
			let sender_key = K256SecretKey::random(&mut OsRng);
			let sender_pubkey = sender_key.public_key();
			let sender_spki = SubjectPublicKeyInfoOwned::from_key(sender_pubkey)?;

			let recipient_key = K256SecretKey::random(&mut OsRng);
			let recipient_pubkey = recipient_key.public_key();

			let wrong_recipient_key = K256SecretKey::random(&mut OsRng); // Different key

			// Create UKM with random bytes
			let ukm_bytes = generate_nonce::<64>(None)?;
			let ukm = UserKeyingMaterial::new(ukm_bytes.to_vec())?;

			// Recipient identifier
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
				issuer: x509_cert::name::Name::default(),
				serial_number: x509_cert::serial_number::SerialNumber::new(&[0x01])?,
			});

			// Key encryption algorithm
			let key_enc_alg = AlgorithmIdentifierOwned { oid: crate::asn1::AES_256_WRAP_OID, parameters: None };

			// Original CEK
			let original_cek = [0x42u8; 32];

			// Build KARI for correct recipient
			let mut builder = TightBeamKariBuilder::default()
				.with_sender_priv(sender_key)
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient_pubkey)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);

			let recipient_info = builder.build(&original_cek).map_err(|e| format!("build failed: {:?}", e))?;

			let kari = match recipient_info {
				RecipientInfo::Kari(k) => k,
				_ => panic!("Expected Kari variant"),
			};

			// Try to process with wrong recipient key - should fail
			let wrong_recipient = TightBeamKariRecipient::with_defaults(wrong_recipient_key);
			let result = wrong_recipient.process_kari(&kari, 0);

			// Should fail to unwrap because derived KEK will be different
			assert!(result.is_err());
			Ok(())
		}
	}
}
