//! KeyAgreeRecipientInfo builder for TightBeam CMS handshake.
//!
//! Implements CMS `RecipientInfoBuilder` trait using ECDH + HKDF + key wrapping
//! to encrypt the content-encryption key for the recipient.

use super::error::KariBuilderError;
use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::crypto::sign::elliptic_curve::{PublicKey, SecretKey};
use crate::der::asn1::BitString;
use crate::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::kari::kari_wrap;

#[cfg(all(feature = "builder", feature = "aead"))]
use crate::cms::builder::{Error as CmsBuilderError, RecipientInfoBuilder, RecipientInfoType};
#[cfg(all(feature = "builder", feature = "aead"))]
use crate::cms::content_info::CmsVersion;
#[cfg(all(feature = "builder", feature = "aead"))]
use crate::cms::enveloped_data::{
	EncryptedKey, KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo, OriginatorIdentifierOrKey, OriginatorPublicKey,
	RecipientEncryptedKey, RecipientInfo, UserKeyingMaterial,
};
#[cfg(all(feature = "builder", feature = "aead"))]
use crate::crypto::profiles::CryptoProvider;
#[cfg(all(feature = "builder", feature = "aead"))]
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
#[cfg(all(feature = "builder", feature = "aead"))]
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic};

/// Builder for `KeyAgreeRecipientInfo` using ECDH + HKDF + key wrapping.
///
/// This builder performs:
/// 1. ECDH between sender ephemeral private key and recipient public key.
/// 2. HKDF derivation using UKM as salt to produce KEK.
/// 3. Key wrapping (e.g., AES Key Wrap RFC 3394) of the content-encryption key.
/// 4. Construction of CMS `KeyAgreeRecipientInfo` structure.
///
/// Generic over `P: CryptoProvider` to allow pluggable cryptographic implementations.
#[cfg(all(feature = "builder", feature = "aead"))]
pub struct TightBeamKariBuilder<P>
where
	P: CryptoProvider,
{
	/// Sender's ephemeral private key for ECDH
	sender_priv: Option<SecretKey<P::Curve>>,
	/// Sender's ephemeral public key (originator)
	sender_pub_spki: Option<SubjectPublicKeyInfoOwned>,
	/// Recipient's public key for ECDH
	recipient_pub: Option<PublicKey<P::Curve>>,
	/// Recipient identifier
	recipient_rid: Option<KeyAgreeRecipientIdentifier>,
	/// User Keying Material (client nonce || server nonce)
	ukm: Option<UserKeyingMaterial>,
	/// Key encryption algorithm OID (ECDH + HKDF profile)
	key_enc_alg: Option<AlgorithmIdentifierOwned>,
	/// HKDF info string for KEK derivation
	kdf_info: &'static [u8],
	/// Cryptographic provider
	provider: P,
}

#[cfg(all(feature = "builder", feature = "aead"))]
impl<P> TightBeamKariBuilder<P>
where
	P: CryptoProvider,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
{
	/// Create a new KARI builder with default KDF (HKDF-SHA3-256) and key wrapper (AES-KW).
	///
	/// This constructor provides a generic implementation that works for any curve type.
	/// The KDF uses SHA3-256 for HKDF derivation, and the key wrapper uses AES Key Wrap (RFC 3394).
	///
	/// Use `with_kdf_info()` to customize the KDF info string for interoperability.
	#[cfg(all(feature = "kdf", feature = "sha3"))]
	pub fn new(provider: P) -> Self {
		Self {
			sender_priv: None,
			sender_pub_spki: None,
			recipient_pub: None,
			recipient_rid: None,
			ukm: None,
			key_enc_alg: None,
			kdf_info: TIGHTBEAM_KARI_KDF_INFO,
			provider,
		}
	}

	/// Set the sender's ephemeral private key for ECDH.
	pub fn with_sender_priv(mut self, sender_priv: SecretKey<P::Curve>) -> Self {
		self.sender_priv = Some(sender_priv);
		self
	}

	/// Set the sender's ephemeral public key (originator) in SPKI format.
	pub fn with_sender_pub_spki(mut self, sender_pub_spki: SubjectPublicKeyInfoOwned) -> Self {
		self.sender_pub_spki = Some(sender_pub_spki);
		self
	}

	/// Set the recipient's static ECDH public key.
	pub fn with_recipient_pub(mut self, recipient_pub: PublicKey<P::Curve>) -> Self {
		self.recipient_pub = Some(recipient_pub);
		self
	}

	/// Set the recipient identifier (IssuerAndSerialNumber or RKeyId).
	pub fn with_recipient_rid(mut self, recipient_rid: KeyAgreeRecipientIdentifier) -> Self {
		self.recipient_rid = Some(recipient_rid);
		self
	}

	/// Set the User Keying Material (clientNonce || serverNonce).
	pub fn with_ukm(mut self, ukm: UserKeyingMaterial) -> Self {
		self.ukm = Some(ukm);
		self
	}

	/// Set the key encryption algorithm identifier (ECDH + HKDF profile).
	pub fn with_key_enc_alg(mut self, key_enc_alg: AlgorithmIdentifierOwned) -> Self {
		self.key_enc_alg = Some(key_enc_alg);
		self
	}

	/// Set the HKDF info string for KEK derivation.
	///
	/// This allows interoperability with other CMS implementations by using
	/// custom KDF parameters while maintaining HKDF-SHA3-256 algorithm.
	///
	/// # Parameters
	/// - `kdf_info`: Custom info string for HKDF (default: `TIGHTBEAM_KARI_KDF_INFO`)
	///
	/// # Example
	/// ```ignore
	/// let builder = TightBeamKariBuilder::new()
	///     .with_kdf_info(b"custom-kdf-info-v1");
	/// ```
	pub fn with_kdf_info(mut self, kdf_info: &'static [u8]) -> Self {
		self.kdf_info = kdf_info;
		self
	}

	/// Build originator field from sender's public key SPKI.
	fn build_originator(&mut self) -> Result<OriginatorIdentifierOrKey, KariBuilderError> {
		let sender_pub_spki = self
			.sender_pub_spki
			.take()
			.ok_or(KariBuilderError::MissingSenderPublicKeySpki)?;

		let algo = sender_pub_spki.algorithm;
		let pub_key_bits = BitString::from_bytes(sender_pub_spki.subject_public_key.raw_bytes())?;

		Ok(OriginatorIdentifierOrKey::OriginatorKey(OriginatorPublicKey {
			algorithm: algo,
			public_key: pub_key_bits,
		}))
	}

	/// Validate that all required fields are set.
	fn validate(&self) -> Result<(), KariBuilderError> {
		if self.sender_priv.is_none() {
			Err(KariBuilderError::MissingSenderPrivateKey)
		} else if self.sender_pub_spki.is_none() {
			Err(KariBuilderError::MissingSenderPublicKeySpki)
		} else if self.recipient_pub.is_none() {
			Err(KariBuilderError::MissingRecipientPublicKey)
		} else if self.recipient_rid.is_none() {
			Err(KariBuilderError::MissingRecipientIdentifier)
		} else if self.ukm.is_none() {
			Err(KariBuilderError::MissingUkm)
		} else if self.key_enc_alg.is_none() {
			Err(KariBuilderError::MissingKeyEncryptionAlgorithm)
		} else {
			Ok(())
		}
	}
}

/// Default implementation for DefaultCryptoProvider (secp256k1 + HKDF-SHA3-256 + AES Key Wrap).
#[cfg(all(
	feature = "builder",
	feature = "aead",
	feature = "secp256k1",
	feature = "kdf",
	feature = "sha3"
))]
impl Default for TightBeamKariBuilder<DefaultCryptoProvider> {
	fn default() -> Self {
		Self {
			sender_priv: None,
			sender_pub_spki: None,
			recipient_pub: None,
			recipient_rid: None,
			ukm: None,
			key_enc_alg: None,
			kdf_info: TIGHTBEAM_KARI_KDF_INFO,
			provider: DefaultCryptoProvider::default(),
		}
	}
}

#[cfg(all(feature = "builder", feature = "aead"))]
impl<P> RecipientInfoBuilder for TightBeamKariBuilder<P>
where
	P: CryptoProvider,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
{
	fn recipient_info_type(&self) -> RecipientInfoType {
		RecipientInfoType::Kari
	}

	fn recipient_info_version(&self) -> CmsVersion {
		CmsVersion::V3
	}

	fn build(&mut self, content_encryption_key: &[u8]) -> Result<RecipientInfo, CmsBuilderError> {
		// 0. Validate required fields
		self.validate()?;

		// 1-3. Perform ECDH + HKDF + AES Key Wrap via centralized core
		let sender_priv = self
			.sender_priv
			.as_ref()
			.ok_or_else(|| CmsBuilderError::Builder("sender_priv not set".into()))?;
		let recipient_pub = self
			.recipient_pub
			.as_ref()
			.ok_or_else(|| CmsBuilderError::Builder("recipient_pub not set".into()))?;
		let ukm = self
			.ukm
			.as_ref()
			.ok_or_else(|| CmsBuilderError::Builder("ukm not set".into()))?;
		let encrypted_key_bytes = kari_wrap(
			&self.provider,
			sender_priv,
			recipient_pub,
			ukm.as_bytes(),
			self.kdf_info,
			content_encryption_key,
		)?;

		// 4. Build encrypted key OctetString
		let encrypted_key = EncryptedKey::new(encrypted_key_bytes)?;

		// 5. Build RecipientEncryptedKey
		let rek = RecipientEncryptedKey {
			rid: self
				.recipient_rid
				.take()
				.ok_or_else(|| CmsBuilderError::Builder("recipient_rid not set".into()))?,
			enc_key: encrypted_key,
		};

		// 6. Build originator
		let originator = self.build_originator()?;

		// 7. Construct KeyAgreeRecipientInfo
		let kari = KeyAgreeRecipientInfo {
			version: CmsVersion::V3,
			originator,
			ukm: self.ukm.take(),
			key_enc_alg: self
				.key_enc_alg
				.take()
				.ok_or_else(|| CmsBuilderError::Builder("key_enc_alg not set".into()))?,
			recipient_enc_keys: vec![rek],
		};

		Ok(RecipientInfo::Kari(kari))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::k256::SecretKey as K256SecretKey;
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::{Decode, Encode};
	use crate::random::{generate_nonce, OsRng};
	use crate::transport::handshake::tests::{
		create_test_key_enc_alg, create_test_keypair, create_test_recipient_id, create_test_ukm,
	};

	/// Helper function to create a fully configured test KARI builder
	fn create_test_kari_builder() -> TightBeamKariBuilder<DefaultCryptoProvider> {
		let (sender_key, sender_spki, _recipient_key, recipient_pubkey) = create_test_keypair();
		let ukm = create_test_ukm();
		let rid = create_test_recipient_id();
		let key_enc_alg = create_test_key_enc_alg();

		TightBeamKariBuilder::default()
			.with_sender_priv(sender_key)
			.with_sender_pub_spki(sender_spki)
			.with_recipient_pub(recipient_pubkey)
			.with_recipient_rid(rid)
			.with_ukm(ukm)
			.with_key_enc_alg(key_enc_alg)
	}

	#[test]
	fn test_validation() {
		let builder = TightBeamKariBuilder::<DefaultCryptoProvider>::default();

		// Should fail validation with all None fields
		let result = builder.validate();
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), KariBuilderError::MissingSenderPrivateKey));
	}

	#[test]
	fn test_fluent_interface() {
		let sender_key = K256SecretKey::random(&mut OsRng);

		// Builder pattern should work
		let builder = TightBeamKariBuilder::<DefaultCryptoProvider>::default()
			.with_sender_priv(sender_key)
			.with_kdf_info(b"test-info");
		assert!(builder.sender_priv.is_some());
		assert_eq!(builder.kdf_info, b"test-info");
	}

	#[test]
	fn test_build_complete_kari() -> Result<(), Box<dyn std::error::Error>> {
		// 1. Create test key pairs and cryptographic materials
		let mut builder = create_test_kari_builder();

		// 2. Generate a CEK to wrap
		let cek = [0x42u8; 32]; // 256-bit CEK

		// 3. Build KARI
		let recipient_info = builder.build(&cek).map_err(|e| format!("build failed: {:?}", e))?;

		// 4. Extract Kari variant (Kari builder should always return Kari)
		let kari = match recipient_info {
			RecipientInfo::Kari(k) => k,
			_ => unreachable!("Kari builder should always return Kari"),
		};

		// 5. Verify the result
		assert_eq!(kari.version, CmsVersion::V3);
		assert_eq!(kari.recipient_enc_keys.len(), 1);

		// Verify originator is set (should always be OriginatorKey for our builder)
		let orig_key = match kari.originator {
			OriginatorIdentifierOrKey::OriginatorKey(k) => k,
			_ => unreachable!("Kari builder should always create OriginatorKey"),
		};

		// Verify it has the right algorithm OID (EC public key)
		assert_eq!(orig_key.algorithm.oid, ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"));
		// Verify UKM is present
		assert!(kari.ukm.is_some());
		assert_eq!(kari.ukm.as_ref().unwrap().as_bytes().len(), 64);
		// Verify key encryption algorithm
		assert_eq!(kari.key_enc_alg.oid, ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"));
		// Verify encrypted key is present and longer than CEK (due to RFC 3394 wrapping)
		assert!(kari.recipient_enc_keys[0].enc_key.as_bytes().len() > cek.len());

		Ok(())
	}

	#[test]
	fn test_kari_serialization() -> Result<(), Box<dyn std::error::Error>> {
		// 1. Create test key pairs
		let (sender_key, sender_spki, _recipient_key, recipient_pubkey) = create_test_keypair();

		// 2. Create UKM with random bytes
		let ukm_bytes = generate_nonce::<64>(None)?;
		let ukm = UserKeyingMaterial::new(ukm_bytes.to_vec())?;

		// 3. Create recipient identifier
		let rid = create_test_recipient_id();

		// 4. Create key encryption algorithm
		let key_enc_alg = create_test_key_enc_alg();

		// 5. Generate CEK
		let cek = [0x33u8; 32];

		// 6. Build KARI
		let mut builder = TightBeamKariBuilder::<DefaultCryptoProvider>::default()
			.with_sender_priv(sender_key)
			.with_sender_pub_spki(sender_spki)
			.with_recipient_pub(recipient_pubkey)
			.with_recipient_rid(rid)
			.with_ukm(ukm)
			.with_key_enc_alg(key_enc_alg);

		let recipient_info = builder.build(&cek).map_err(|e| format!("build failed: {:?}", e))?;

		// 7. Serialize to DER
		let der_bytes = recipient_info.to_der()?;
		assert!(!der_bytes.is_empty());

		// 8. Deserialize back
		let decoded = RecipientInfo::from_der(&der_bytes)?;

		// 9. Verify round-trip (should deserialize back to Kari)
		let kari = match decoded {
			RecipientInfo::Kari(k) => k,
			_ => unreachable!("Deserialized Kari should be Kari"),
		};

		assert_eq!(kari.version, CmsVersion::V3);
		assert!(kari.ukm.is_some());
		assert_eq!(kari.recipient_enc_keys.len(), 1);

		Ok(())
	}
}
