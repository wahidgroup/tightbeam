//! KeyAgreeRecipientInfo recipient processor for the TightBeam CMS handshake.
//!
//! The processor extracts the content-encryption key (CEK) from a received
//! KARI structure.

use crate::cms::enveloped_data::{KeyAgreeRecipientInfo, OriginatorIdentifierOrKey, RecipientInfo};
use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use crate::crypto::secret::SecretSlice;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, FieldBytesSize, PublicKey, SecretKey};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::kari::{HandshakeAgreement, HandshakeKek, Kek};
use crate::transport::handshake::primitives::{KdfInfo, KdfSalt};

/// Recipient-side processor for `KeyAgreeRecipientInfo`.
///
/// The processor extracts the content-encryption key (CEK) from a received
/// KARI in four steps:
///
/// 1. Extract the originator's public key from the KARI.
/// 2. Perform ECDH with the recipient's private key.
/// 3. Derive the KEK with the same KDF and UKM as the sender.
/// 4. Unwrap the encrypted key to get the CEK.
///
/// The type is generic over `P: CryptoProvider`, which defines the complete
/// cryptographic suite.
pub struct TightBeamKariRecipient<P>
where
	P: CryptoProvider,
{
	/// The recipient's private key for ECDH.
	recipient_priv: SecretKey<P::Curve>,
	/// The HKDF info string, which MUST match the sender's.
	kdf_info: &'static [u8],
	/// The cryptographic provider.
	provider: P,
}

impl<P> TightBeamKariRecipient<P>
where
	P: CryptoProvider,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	FieldBytesSize<P::Curve>: ModulusSize,
{
	/// Create a KARI recipient processor that uses `recipient_priv` for the
	/// ECDH and the default `TIGHTBEAM_KARI_KDF_INFO` label.
	pub fn new(provider: P, recipient_priv: SecretKey<P::Curve>) -> Self {
		Self::with_kdf_info(provider, recipient_priv, TIGHTBEAM_KARI_KDF_INFO)
	}

	/// Create a KARI recipient processor with a custom KDF label.
	///
	/// `kdf_info` MUST match the sender's. A custom label interoperates with
	/// senders that use other KDF parameters while the provider's KDF algorithm
	/// stays fixed.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::crypto::sign::ecdsa::k256::SecretKey;
	/// use tightbeam::random::OsRng;
	/// use tightbeam::transport::handshake::TightBeamKariRecipient;
	///
	/// let provider = DefaultCryptoProvider::default();
	/// let recipient_key = SecretKey::random(&mut OsRng);
	/// let processor = TightBeamKariRecipient::with_kdf_info(provider, recipient_key, b"custom-kdf-info-v1");
	/// ```
	pub fn with_kdf_info(provider: P, recipient_priv: SecretKey<P::Curve>, kdf_info: &'static [u8]) -> Self {
		Self { recipient_priv, kdf_info, provider }
	}

	/// Process a KeyAgreeRecipientInfo and answer the unwrapped
	/// content-encryption key (CEK).
	///
	/// `recipient_index` selects the entry in `recipient_enc_keys`, usually 0.
	pub fn process_kari(
		&self,
		kari: &KeyAgreeRecipientInfo,
		recipient_index: usize,
	) -> Result<SecretSlice<u8>, HandshakeError> {
		// 1. Validate the recipient index.
		if recipient_index >= kari.recipient_enc_keys.len() {
			return Err(HandshakeError::InvalidRecipientIndex);
		}

		// 2. Extract the originator's public key.
		let originator_pub = self.extract_originator_public_key(kari)?;

		// 3-6. Unwrap through ECDH, HKDF and the integrity re-wrap
		let ukm = kari.ukm.as_ref().ok_or(HandshakeError::MissingUkm)?;
		let wrapped_key = kari.recipient_enc_keys[recipient_index].enc_key.as_bytes();
		let shared_secret = self.recipient_priv.shared_secret(&originator_pub)?;
		let ukm_salt = KdfSalt::new(ukm.as_bytes());
		let kari_label = KdfInfo::new(self.kdf_info);

		let kek = shared_secret.derive_kek::<P>(ukm_salt, kari_label)?;
		Kek::new(kek.as_slice()).unwrap_verified(&self.provider, wrapped_key)
	}

	/// Extract the originator's public key from the KARI.
	fn extract_originator_public_key(
		&self,
		kari: &KeyAgreeRecipientInfo,
	) -> Result<PublicKey<P::Curve>, HandshakeError> {
		match &kari.originator {
			OriginatorIdentifierOrKey::OriginatorKey(orig_key) => {
				// Read the raw public key bytes from the BitString.
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

/// A KARI recipient extracts the CEK for an EnvelopedData processor.
impl<P> super::enveloped_data::RecipientProcessor for TightBeamKariRecipient<P>
where
	P: CryptoProvider,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	FieldBytesSize<P::Curve>: ModulusSize,
{
	fn process_recipient(
		&self,
		info: &RecipientInfo,
		recipient_index: usize,
	) -> Result<SecretSlice<u8>, HandshakeError> {
		match info {
			RecipientInfo::Kari(kari) => self.process_kari(kari, recipient_index),
			_ => Err(HandshakeError::UnsupportedOriginatorIdentifier),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::secret::ToInsecure;

	mod recipient {
		use super::*;
		use crate::cms::builder::RecipientInfoBuilder;
		use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, RecipientInfo, UserKeyingMaterial};
		use crate::crypto::sign::ecdsa::k256::SecretKey as K256SecretKey;
		use crate::oids::AES_256_WRAP;
		use crate::random::{generate_nonce, OsRng};
		use crate::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
		use crate::transport::handshake::builders::kari::TightBeamKariBuilder;

		/// Unwrap the KARI variant a [`TightBeamKariBuilder`] must produce.
		fn open_kari(recipient_info: RecipientInfo) -> KeyAgreeRecipientInfo {
			match recipient_info {
				RecipientInfo::Kari(kari) => kari,
				other => panic!("builder must produce a Kari recipient, got {other:?}"),
			}
		}

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

			// Build the recipient identifier.
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
				issuer: x509_cert::name::Name::default(),
				serial_number: x509_cert::serial_number::SerialNumber::new(&[0x01])?,
			});

			// Choose the key encryption algorithm.
			let key_enc_alg = AlgorithmIdentifierOwned { oid: AES_256_WRAP, parameters: None };

			// The original CEK.
			let original_cek = [0x42u8; 32];

			// Sender side: build the KARI.
			let sender_priv = sender_key.clone();
			let mut builder = TightBeamKariBuilder::default()
				.with_sender_priv(sender_priv)
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient_pubkey)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);

			let recipient_info = builder.build(&original_cek).map_err(HandshakeError::CmsBuilderError)?;
			let kari = open_kari(recipient_info);

			// Recipient side: process the KARI.
			let recipient = TightBeamKariRecipient::with_defaults(recipient_key);
			let extracted_cek = recipient.process_kari(&kari, 0)?;

			// The extracted CEK matches the original.
			assert_eq!(extracted_cek.to_insecure().as_slice(), original_cek.as_slice());
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

			// Build the recipient identifier.
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
				issuer: x509_cert::name::Name::default(),
				serial_number: x509_cert::serial_number::SerialNumber::new(&[0x01])?,
			});

			// Choose the key encryption algorithm.
			let key_enc_alg = AlgorithmIdentifierOwned { oid: AES_256_WRAP, parameters: None };

			// The original CEK.
			let original_cek = [0x42u8; 32];

			// Build the KARI for the correct recipient.
			let mut builder = TightBeamKariBuilder::default()
				.with_sender_priv(sender_key)
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient_pubkey)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);

			let recipient_info = builder.build(&original_cek).map_err(HandshakeError::CmsBuilderError)?;
			let kari = open_kari(recipient_info);

			// Process with the wrong recipient key.
			let wrong_recipient = TightBeamKariRecipient::with_defaults(wrong_recipient_key);
			let result = wrong_recipient.process_kari(&kari, 0);

			// The unwrap fails, because the derived KEK differs.
			assert!(result.is_err());
			Ok(())
		}
	}
}
