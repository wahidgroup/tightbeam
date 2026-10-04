//! KeyAgreeRecipientInfo builder for the TightBeam CMS handshake.
//!
//! The builder implements the CMS `RecipientInfoBuilder` trait. It encrypts
//! the content-encryption key (CEK) for the recipient through ECDH, HKDF, and
//! key wrapping.

use super::error::KariBuilderError;
use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::crypto::sign::elliptic_curve::{PublicKey, SecretKey};
use crate::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::kari::{HandshakeKek, Kek, OriginatorKey};
use crate::transport::handshake::primitives::{KdfInfo, KdfSalt};
use crate::transport::handshake::schedule::HandshakeAgreement;

#[cfg(all(feature = "builder", feature = "aead"))]
use crate::cms::builder::{Error as CmsBuilderError, RecipientInfoBuilder, RecipientInfoType};
#[cfg(all(feature = "builder", feature = "aead"))]
use crate::cms::content_info::CmsVersion;
#[cfg(all(feature = "builder", feature = "aead"))]
use crate::cms::enveloped_data::{
	EncryptedKey, KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo, OriginatorIdentifierOrKey, RecipientEncryptedKey,
	RecipientInfo, UserKeyingMaterial,
};
#[cfg(all(feature = "builder", feature = "aead"))]
use crate::crypto::profiles::CryptoProvider;
#[cfg(all(feature = "builder", feature = "aead"))]
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
#[cfg(all(feature = "builder", feature = "aead"))]
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic};

/// Builder for `KeyAgreeRecipientInfo` with ECDH, HKDF, and key wrapping.
///
/// The builder wraps the content-encryption key (CEK) in four steps:
///
/// 1. Perform ECDH between the sender's ephemeral private key and the recipient's public key.
/// 2. Derive the KEK through HKDF with the UKM as salt.
/// 3. Wrap the CEK under the KEK with AES Key Wrap (RFC 3394).
/// 4. Construct the CMS `KeyAgreeRecipientInfo` structure.
///
/// The type is generic over `P: CryptoProvider`, which supplies the
/// cryptographic implementations.
#[cfg(all(feature = "builder", feature = "aead"))]
pub struct TightBeamKariBuilder<P>
where
	P: CryptoProvider,
{
	/// The sender's ephemeral private key for ECDH.
	sender_priv: Option<SecretKey<P::Curve>>,
	/// The sender's ephemeral public key, which the KARI carries as originator.
	sender_pub_spki: Option<SubjectPublicKeyInfoOwned>,
	/// The recipient's public key for ECDH.
	recipient_pub: Option<PublicKey<P::Curve>>,
	/// The identifier of the recipient the KARI names.
	recipient_rid: Option<KeyAgreeRecipientIdentifier>,
	/// The User Keying Material (UKM), which salts the KEK derivation.
	ukm: Option<UserKeyingMaterial>,
	/// The key encryption algorithm identifier the KARI carries.
	key_enc_alg: Option<AlgorithmIdentifierOwned>,
	/// The HKDF info string for the KEK derivation.
	kdf_info: &'static [u8],
	/// The cryptographic provider.
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
	/// Create a KARI builder on `provider`, with any curve the provider names.
	///
	/// The provider's KDF, HKDF-SHA3-256 on [`DefaultCryptoProvider`], derives
	/// the KEK, and its AES Key Wrap (RFC 3394) wraps the CEK. Use
	/// [`Self::with_kdf_info`] to set a custom KDF info string for
	/// interoperability.
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

	/// Set the User Keying Material (UKM), which salts the KEK derivation.
	pub fn with_ukm(mut self, ukm: UserKeyingMaterial) -> Self {
		self.ukm = Some(ukm);
		self
	}

	/// Set the key encryption algorithm identifier the KARI carries.
	pub fn with_key_enc_alg(mut self, key_enc_alg: AlgorithmIdentifierOwned) -> Self {
		self.key_enc_alg = Some(key_enc_alg);
		self
	}

	/// Set the HKDF info string for KEK derivation.
	///
	/// A custom label interoperates with other CMS implementations while the
	/// provider's KDF algorithm stays fixed. The default is
	/// `TIGHTBEAM_KARI_KDF_INFO`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::transport::handshake::TightBeamKariBuilder;
	///
	/// let provider = DefaultCryptoProvider::default();
	/// let builder = TightBeamKariBuilder::new(provider).with_kdf_info(b"custom-kdf-info-v1");
	/// ```
	pub fn with_kdf_info(mut self, kdf_info: &'static [u8]) -> Self {
		self.kdf_info = kdf_info;
		self
	}

	/// Build the originator field from the sender's public key SPKI.
	fn build_originator(&mut self) -> Result<OriginatorIdentifierOrKey, KariBuilderError> {
		let sender_pub_spki = self
			.sender_pub_spki
			.take()
			.ok_or(KariBuilderError::MissingSenderPublicKeySpki)?;

		Ok(OriginatorIdentifierOrKey::OriginatorKey(sender_pub_spki.originator_key()?))
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

/// An empty builder on [`DefaultCryptoProvider`], which runs secp256k1,
/// HKDF-SHA3-256, and AES Key Wrap.
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
		// 0. Validate the required fields.
		self.validate()?;

		// 1-3. Perform the ECDH, the HKDF derivation, and the AES Key Wrap.
		let sender_priv = self.sender_priv.as_ref().ok_or(KariBuilderError::MissingSenderPrivateKey)?;
		let recipient_pub = self.recipient_pub.as_ref().ok_or(KariBuilderError::MissingRecipientPublicKey)?;
		let ukm = self.ukm.as_ref().ok_or(KariBuilderError::MissingUkm)?;
		let shared_secret = sender_priv.shared_secret(recipient_pub)?;
		let ukm_salt = KdfSalt::new(ukm.as_bytes());
		let kari_label = KdfInfo::new(self.kdf_info);
		let kek = shared_secret.derive_kek::<P>(ukm_salt, kari_label)?;
		let encrypted_key_bytes = Kek::new(kek.as_slice()).wrap(&self.provider, content_encryption_key)?;

		// 4. Build the encrypted key OCTET STRING.
		let encrypted_key = EncryptedKey::new(encrypted_key_bytes)?;

		// 5. Build the `RecipientEncryptedKey`.
		let rek = RecipientEncryptedKey {
			rid: self.recipient_rid.take().ok_or(KariBuilderError::MissingRecipientIdentifier)?,
			enc_key: encrypted_key,
		};

		// 6. Build the originator.
		let originator = self.build_originator()?;

		// 7. Construct the `KeyAgreeRecipientInfo`.
		let kari = KeyAgreeRecipientInfo {
			version: CmsVersion::V3,
			originator,
			ukm: self.ukm.take(),
			key_enc_alg: self.key_enc_alg.take().ok_or(KariBuilderError::MissingKeyEncryptionAlgorithm)?,
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

	/// A test KARI builder with every required field set.
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
		// Validation fails at the first missing field, which is the sender
		// private key.
		let result = builder.validate();
		assert!(matches!(result, Err(KariBuilderError::MissingSenderPrivateKey)));
	}

	#[test]
	fn test_fluent_interface() {
		let sender_key = K256SecretKey::random(&mut OsRng);

		let builder = TightBeamKariBuilder::<DefaultCryptoProvider>::default()
			.with_sender_priv(sender_key)
			.with_kdf_info(b"test-info");
		assert!(builder.sender_priv.is_some());
		assert_eq!(builder.kdf_info, b"test-info");
	}

	#[test]
	fn test_build_complete_kari() -> Result<(), Box<dyn std::error::Error>> {
		// 1. Create a builder over test key pairs and cryptographic materials.
		let mut builder = create_test_kari_builder();

		// 2. Choose a CEK to wrap.
		let cek = [0x42u8; 32]; // 256-bit CEK

		// 3. Build the KARI.
		let recipient_info = builder.build(&cek).map_err(|e| format!("build failed: {e:?}"))?;

		// 4. Extract the Kari variant, which a KARI builder always returns.
		let kari = match recipient_info {
			RecipientInfo::Kari(k) => k,
			_ => unreachable!("Kari builder should always return Kari"),
		};

		// 5. Verify the result.
		assert_eq!(kari.version, CmsVersion::V3);
		assert_eq!(kari.recipient_enc_keys.len(), 1);

		// The originator is an `OriginatorKey`, which this builder always
		// creates.
		let orig_key = match kari.originator {
			OriginatorIdentifierOrKey::OriginatorKey(k) => k,
			_ => unreachable!("Kari builder should always create OriginatorKey"),
		};

		// The originator carries the EC public key algorithm OID.
		assert_eq!(orig_key.algorithm.oid, ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"));
		// The UKM is present and 64 bytes long.
		assert!(matches!(kari.ukm.as_ref(), Some(ukm) if ukm.as_bytes().len() == 64));
		// The key encryption algorithm is AES-256 key wrap.
		assert_eq!(kari.key_enc_alg.oid, ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"));
		// The encrypted key is present and longer than the CEK, because of the
		// RFC 3394 wrapping.
		assert!(kari.recipient_enc_keys[0].enc_key.as_bytes().len() > cek.len());

		Ok(())
	}

	#[test]
	fn test_kari_serialization() -> Result<(), Box<dyn std::error::Error>> {
		// 1. Create the test key pairs.
		let (sender_key, sender_spki, _recipient_key, recipient_pubkey) = create_test_keypair();

		// 2. Create the UKM from random bytes.
		let ukm_bytes = generate_nonce::<64>(None)?;
		let ukm = UserKeyingMaterial::new(ukm_bytes.to_vec())?;

		// 3. Create the recipient identifier.
		let rid = create_test_recipient_id();

		// 4. Create the key encryption algorithm.
		let key_enc_alg = create_test_key_enc_alg();

		// 5. Choose the CEK.
		let cek = [0x33u8; 32];

		// 6. Build the KARI.
		let mut builder = TightBeamKariBuilder::<DefaultCryptoProvider>::default()
			.with_sender_priv(sender_key)
			.with_sender_pub_spki(sender_spki)
			.with_recipient_pub(recipient_pubkey)
			.with_recipient_rid(rid)
			.with_ukm(ukm)
			.with_key_enc_alg(key_enc_alg);

		let recipient_info = builder.build(&cek).map_err(|e| format!("build failed: {e:?}"))?;

		// 7. Serialize it to DER.
		let der_bytes = recipient_info.to_der()?;
		assert!(!der_bytes.is_empty());

		// 8. Deserialize it back.
		let decoded = RecipientInfo::from_der(&der_bytes)?;

		// 9. Verify the round trip, which deserializes back to a Kari.
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
