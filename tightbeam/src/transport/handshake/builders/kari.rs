//! KeyAgreeRecipientInfo builder for TightBeam CMS handshake.
//!
//! Implements CMS `RecipientInfoBuilder` trait using ECDH + HKDF + key wrapping
//! to encrypt the content-encryption key for the recipient.

use super::error::KariBuilderError;
use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
use crate::transport::handshake::error::HandshakeError;
use der::asn1::BitString;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

#[cfg(all(feature = "builder", feature = "aead"))]
use cms::builder::{Error as CmsBuilderError, RecipientInfoBuilder, RecipientInfoType};
#[cfg(all(feature = "builder", feature = "aead"))]
use cms::content_info::CmsVersion;
#[cfg(all(feature = "builder", feature = "aead"))]
use cms::enveloped_data::{
	EncryptedKey, KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo, OriginatorIdentifierOrKey, OriginatorPublicKey,
	RecipientEncryptedKey, RecipientInfo, UserKeyingMaterial,
};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use elliptic_curve::ecdh::diffie_hellman;
use elliptic_curve::{PublicKey, SecretKey};

#[cfg(feature = "kdf")]
use hkdf::Hkdf;

/// Builder for `KeyAgreeRecipientInfo` using ECDH + HKDF + key wrapping.
///
/// This builder performs:
/// 1. ECDH between sender ephemeral private key and recipient public key.
/// 2. HKDF derivation using UKM as salt to produce KEK.
/// 3. Key wrapping (e.g., AES Key Wrap RFC 3394) of the content-encryption key.
/// 4. Construction of CMS `KeyAgreeRecipientInfo` structure.
#[cfg(all(feature = "builder", feature = "aead"))]
pub struct TightBeamKariBuilder<C>
where
	C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
{
	/// Sender's ephemeral private key for ECDH
	sender_priv: Option<SecretKey<C>>,
	/// Sender's ephemeral public key (originator)
	sender_pub_spki: Option<SubjectPublicKeyInfoOwned>,
	/// Recipient's public key for ECDH
	recipient_pub: Option<PublicKey<C>>,
	/// Recipient identifier
	recipient_rid: Option<KeyAgreeRecipientIdentifier>,
	/// User Keying Material (client nonce || server nonce)
	ukm: Option<UserKeyingMaterial>,
	/// Key encryption algorithm OID (ECDH + HKDF profile)
	key_enc_alg: Option<AlgorithmIdentifierOwned>,
	/// HKDF info string for KEK derivation
	kdf_info: &'static [u8],
	/// KDF function (takes shared secret, salt, info, and output length)
	kdf: Box<dyn Fn(&[u8], &[u8], &[u8], usize) -> Result<Vec<u8>, HandshakeError>>,
	/// Key wrap function (takes CEK and KEK, returns wrapped key)
	key_wrapper: Box<dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, HandshakeError>>,
}

#[cfg(all(feature = "builder", feature = "aead"))]
impl<C> TightBeamKariBuilder<C>
where
	C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
{
	/// Create a new KARI builder with default KDF (HKDF-SHA3-256) and key wrapper (AES-KW).
	///
	/// This constructor provides a generic implementation that works for any curve type.
	/// The KDF uses SHA3-256 for HKDF derivation, and the key wrapper uses AES Key Wrap (RFC 3394).
	#[cfg(all(feature = "kdf", feature = "sha3"))]
	pub fn new() -> Self {
		Self {
			sender_priv: None,
			sender_pub_spki: None,
			recipient_pub: None,
			recipient_rid: None,
			ukm: None,
			key_enc_alg: None,
			kdf_info: TIGHTBEAM_KARI_KDF_INFO,
			kdf: Box::new(hkdf_sha3_256),
			key_wrapper: Box::new(aes_key_wrap),
		}
	}

	/// Set the sender's ephemeral private key for ECDH.
	pub fn with_sender_priv(mut self, sender_priv: SecretKey<C>) -> Self {
		self.sender_priv = Some(sender_priv);
		self
	}

	/// Set the sender's ephemeral public key (originator) in SPKI format.
	pub fn with_sender_pub_spki(mut self, sender_pub_spki: SubjectPublicKeyInfoOwned) -> Self {
		self.sender_pub_spki = Some(sender_pub_spki);
		self
	}

	/// Set the recipient's static ECDH public key.
	pub fn with_recipient_pub(mut self, recipient_pub: PublicKey<C>) -> Self {
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
	pub fn with_kdf_info(mut self, kdf_info: &'static [u8]) -> Self {
		self.kdf_info = kdf_info;
		self
	}

	/// Set a custom KDF function.
	pub fn with_kdf(mut self, kdf: Box<dyn Fn(&[u8], &[u8], &[u8], usize) -> Result<Vec<u8>, HandshakeError>>) -> Self {
		self.kdf = kdf;
		self
	}

	/// Set a custom key wrapper function.
	pub fn with_key_wrapper(
		mut self,
		key_wrapper: Box<dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, HandshakeError>>,
	) -> Self {
		self.key_wrapper = key_wrapper;
		self
	}

	/// Perform ECDH and derive shared secret.
	fn derive_shared_secret(&self) -> Result<Vec<u8>, KariBuilderError> {
		let sender_priv = self.sender_priv.as_ref().ok_or(KariBuilderError::MissingSenderPrivateKey)?;
		let recipient_pub = self.recipient_pub.as_ref().ok_or(KariBuilderError::MissingRecipientPublicKey)?;

		let shared_secret = diffie_hellman(sender_priv.to_nonzero_scalar(), recipient_pub.as_affine());
		Ok(shared_secret.raw_secret_bytes().as_ref().to_vec())
	}

	/// Derive key-encryption key (KEK) using configured KDF.
	///
	/// Salt = UKM (clientNonce || serverNonce)
	/// Info = self.kdf_info (e.g., `TIGHTBEAM_KARI_KDF_INFO`)
	/// Output = 32 bytes (AES-256 KEK)
	fn derive_kek(&self, shared_secret: &[u8]) -> Result<Vec<u8>, KariBuilderError> {
		let ukm = self.ukm.as_ref().ok_or(KariBuilderError::MissingUkm)?;
		let salt = ukm.as_bytes();
		(self.kdf)(shared_secret, salt, self.kdf_info, 32).map_err(|_| KariBuilderError::MissingUkm)
	}

	/// Wrap content-encryption key using provided key wrapper function.
	///
	/// # Parameters
	/// - `cek`: Content-encryption key to wrap
	/// - `kek`: Key-encryption key
	fn wrap_cek(&self, cek: &[u8], kek: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		(self.key_wrapper)(cek, kek)
	}

	/// Build originator field from sender's public key SPKI.
	fn build_originator(&self) -> Result<OriginatorIdentifierOrKey, KariBuilderError> {
		let sender_pub_spki = self
			.sender_pub_spki
			.as_ref()
			.ok_or(KariBuilderError::MissingSenderPublicKeySpki)?;

		let algo = sender_pub_spki.algorithm.clone();
		let pub_key_bits = BitString::from_bytes(sender_pub_spki.subject_public_key.raw_bytes())
			.map_err(|_| KariBuilderError::MissingSenderPublicKeySpki)?;

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

/// Default implementation for secp256k1 + HKDF-SHA3-256 + AES Key Wrap.
#[cfg(all(
	feature = "builder",
	feature = "aead",
	feature = "secp256k1",
	feature = "kdf",
	feature = "sha3"
))]
impl Default for TightBeamKariBuilder<k256::Secp256k1> {
	fn default() -> Self {
		Self {
			sender_priv: None,
			sender_pub_spki: None,
			recipient_pub: None,
			recipient_rid: None,
			ukm: None,
			key_enc_alg: None,
			kdf_info: TIGHTBEAM_KARI_KDF_INFO,
			kdf: Box::new(hkdf_sha3_256),
			key_wrapper: Box::new(aes_key_wrap),
		}
	}
}

/// HKDF-SHA3-256 KDF implementation.
#[cfg(all(feature = "kdf", feature = "sha3"))]
pub(crate) fn hkdf_sha3_256(
	shared_secret: &[u8],
	salt: &[u8],
	info: &[u8],
	out_len: usize,
) -> Result<Vec<u8>, HandshakeError> {
	let hk = Hkdf::<sha3::Sha3_256>::new(Some(salt), shared_secret);
	let mut output = vec![0u8; out_len];
	hk.expand(info, &mut output).map_err(|_| HandshakeError::KdfError)?;
	Ok(output)
}

/// AES Key Wrap (RFC 3394) implementation using aes-kw crate.
#[cfg(all(feature = "builder", feature = "aead"))]
pub(crate) fn aes_key_wrap(cek: &[u8], kek: &[u8]) -> Result<Vec<u8>, HandshakeError> {
	use aes_kw::Kek;

	// Validate KEK size (16, 24, or 32 bytes for AES-128/192/256)
	if ![16, 24, 32].contains(&kek.len()) {
		return Err(HandshakeError::InvalidKeySize { expected: 32, received: kek.len() });
	}

	// Validate CEK size (must be multiple of 8, minimum 16 bytes)
	if cek.len() < 16 || cek.len() % 8 != 0 {
		return Err(HandshakeError::InvalidKeySize {
			expected: 16, // minimum
			received: cek.len(),
		});
	}

	// Create KEK based on key size and wrap the CEK
	let wrapped = match kek.len() {
		16 => {
			let kek_array: &[u8; 16] = kek
				.try_into()
				.map_err(|_| HandshakeError::InvalidKeySize { expected: 16, received: kek.len() })?;
			let kek_obj = Kek::<aes::Aes128>::from(*kek_array);
			kek_obj.wrap_vec(cek)?
		}
		24 => {
			let kek_array: &[u8; 24] = kek
				.try_into()
				.map_err(|_| HandshakeError::InvalidKeySize { expected: 24, received: kek.len() })?;
			let kek_obj = Kek::<aes::Aes192>::from(*kek_array);
			kek_obj.wrap_vec(cek)?
		}
		32 => {
			let kek_array: &[u8; 32] = kek
				.try_into()
				.map_err(|_| HandshakeError::InvalidKeySize { expected: 32, received: kek.len() })?;
			let kek_obj = Kek::<aes::Aes256>::from(*kek_array);
			kek_obj.wrap_vec(cek)?
		}
		_ => unreachable!("KEK size already validated"),
	};

	Ok(wrapped)
}

/// AES Key Unwrap (RFC 3394) implementation using aes-kw crate.
///
/// Unwraps a wrapped CEK using the provided KEK. This is the inverse operation
/// of `aes_key_wrap` and is used by the recipient to extract the CEK.
///
/// # Parameters
/// - `wrapped_cek`: The wrapped content-encryption key (includes 8-byte IV)
/// - `kek`: Key-encryption key (16, 24, or 32 bytes for AES-128/192/256)
///
/// # Returns
/// The unwrapped CEK on success, or an error if unwrapping fails.
#[cfg(all(feature = "builder", feature = "aead"))]
pub(crate) fn aes_key_unwrap(wrapped_cek: &[u8], kek: &[u8]) -> Result<Vec<u8>, HandshakeError> {
	use aes_kw::Kek;

	// Validate KEK size (16, 24, or 32 bytes for AES-128/192/256)
	if ![16, 24, 32].contains(&kek.len()) {
		return Err(HandshakeError::InvalidKeySize { expected: 32, received: kek.len() });
	}

	// Validate wrapped CEK size (must be at least 24 bytes: 8-byte IV + minimum 16-byte key)
	if wrapped_cek.len() < 24 || wrapped_cek.len() % 8 != 0 {
		return Err(HandshakeError::InvalidKeySize {
			expected: 24, // minimum
			received: wrapped_cek.len(),
		});
	}

	// Create KEK based on key size and unwrap the CEK
	let unwrapped = match kek.len() {
		16 => {
			let kek_array: &[u8; 16] = kek
				.try_into()
				.map_err(|_| HandshakeError::InvalidKeySize { expected: 16, received: kek.len() })?;
			let kek_obj = Kek::<aes::Aes128>::from(*kek_array);
			kek_obj.unwrap_vec(wrapped_cek)?
		}
		24 => {
			let kek_array: &[u8; 24] = kek
				.try_into()
				.map_err(|_| HandshakeError::InvalidKeySize { expected: 24, received: kek.len() })?;
			let kek_obj = Kek::<aes::Aes192>::from(*kek_array);
			kek_obj.unwrap_vec(wrapped_cek)?
		}
		32 => {
			let kek_array: &[u8; 32] = kek
				.try_into()
				.map_err(|_| HandshakeError::InvalidKeySize { expected: 32, received: kek.len() })?;
			let kek_obj = Kek::<aes::Aes256>::from(*kek_array);
			kek_obj.unwrap_vec(wrapped_cek)?
		}
		_ => unreachable!("KEK size already validated"),
	};

	Ok(unwrapped)
}

#[cfg(all(feature = "builder", feature = "aead"))]
impl<C> RecipientInfoBuilder for TightBeamKariBuilder<C>
where
	C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
{
	fn recipient_info_type(&self) -> RecipientInfoType {
		RecipientInfoType::Kari
	}

	fn recipient_info_version(&self) -> CmsVersion {
		CmsVersion::V3
	}

	fn build(&mut self, content_encryption_key: &[u8]) -> Result<RecipientInfo, CmsBuilderError> {
		// 0. Validate required fields
		self.validate()
			.map_err(|e| CmsBuilderError::Builder(format!("Validation failed: {:?}", e)))?;

		// 1. Perform ECDH
		let shared_secret = self
			.derive_shared_secret()
			.map_err(|e| CmsBuilderError::Builder(format!("ECDH failed: {:?}", e)))?;

		// 2. Derive KEK via configured KDF
		let mut kek = self
			.derive_kek(&shared_secret)
			.map_err(|e| CmsBuilderError::Builder(format!("HKDF failed: {:?}", e)))?;

		// 3. Wrap CEK with KEK
		let encrypted_key_bytes = self
			.wrap_cek(content_encryption_key, &kek)
			.map_err(|e| CmsBuilderError::Builder(format!("Key wrap failed: {:?}", e)))?;

		#[cfg(feature = "zeroize")]
		kek.zeroize();

		// 4. Build encrypted key OctetString
		let encrypted_key = EncryptedKey::new(encrypted_key_bytes).map_err(CmsBuilderError::Asn1)?;

		// 5. Build RecipientEncryptedKey
		let rek = RecipientEncryptedKey {
			rid: self
				.recipient_rid
				.clone()
				.ok_or_else(|| CmsBuilderError::Builder("recipient_rid not set".into()))?,
			enc_key: encrypted_key,
		};

		// 6. Build originator
		let originator = self
			.build_originator()
			.map_err(|e| CmsBuilderError::Builder(format!("Originator build failed: {:?}", e)))?;

		// 7. Construct KeyAgreeRecipientInfo
		let kari = KeyAgreeRecipientInfo {
			version: CmsVersion::V3,
			originator,
			ukm: self.ukm.clone(),
			key_enc_alg: self
				.key_enc_alg
				.clone()
				.ok_or_else(|| CmsBuilderError::Builder("key_enc_alg not set".into()))?,
			recipient_enc_keys: vec![rek],
		};

		Ok(RecipientInfo::Kari(kari))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(all(
		feature = "builder",
		feature = "aead",
		feature = "secp256k1",
		feature = "kdf",
		feature = "sha3"
	))]
	mod aes_key_wrap {
		use super::*;

		#[test]
		fn test_basic() {
			let kek = [
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
			];
			let cek = [
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			];

			let wrapped = aes_key_wrap(&cek, &kek).expect("wrap should succeed");
			// Wrapped output should be 8 bytes longer than input (IV + input)
			assert_eq!(wrapped.len(), cek.len() + 8);
		}

		#[test]
		fn test_invalid_kek_size() {
			let kek = [0u8; 15]; // Invalid size
			let cek = [0u8; 32];

			let result = aes_key_wrap(&cek, &kek);
			assert!(result.is_err());
			assert!(matches!(result.unwrap_err(), HandshakeError::InvalidKeySize { .. }));
		}

		#[test]
		fn test_invalid_cek_size() {
			let kek = [0u8; 32];
			let cek = [0u8; 15]; // Not multiple of 8

			let result = aes_key_wrap(&cek, &kek);
			assert!(result.is_err());
			assert!(matches!(result.unwrap_err(), HandshakeError::InvalidKeySize { .. }));
		}

		#[test]
		fn test_cek_too_small() {
			let kek = [0u8; 32];
			let cek = [0u8; 8]; // Minimum is 16 bytes

			let result = aes_key_wrap(&cek, &kek);
			assert!(result.is_err());
			assert!(matches!(result.unwrap_err(), HandshakeError::InvalidKeySize { .. }));
		}

		#[test]
		fn test_different_key_sizes() {
			let cek = [0u8; 32];

			// AES-128 (16-byte KEK)
			let kek_128 = [0u8; 16];
			let wrapped_128 = aes_key_wrap(&cek, &kek_128).expect("AES-128 wrap should succeed");
			assert_eq!(wrapped_128.len(), 40);

			// AES-192 (24-byte KEK)
			let kek_192 = [0u8; 24];
			let wrapped_192 = aes_key_wrap(&cek, &kek_192).expect("AES-192 wrap should succeed");
			assert_eq!(wrapped_192.len(), 40);

			// AES-256 (32-byte KEK)
			let kek_256 = [0u8; 32];
			let wrapped_256 = aes_key_wrap(&cek, &kek_256).expect("AES-256 wrap should succeed");
			assert_eq!(wrapped_256.len(), 40);

			// All should produce different results
			assert_ne!(wrapped_128, wrapped_192);
			assert_ne!(wrapped_192, wrapped_256);
			assert_ne!(wrapped_128, wrapped_256);
		}

		#[test]
		fn test_unwrap_basic() {
			let kek = [
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
			];
			let cek = [
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			];

			// Wrap then unwrap
			let wrapped = aes_key_wrap(&cek, &kek).expect("wrap should succeed");
			let unwrapped = aes_key_unwrap(&wrapped, &kek).expect("unwrap should succeed");

			// Should get back original CEK
			assert_eq!(unwrapped, cek);
		}

		#[test]
		fn test_unwrap_invalid_kek_size() {
			let kek = [0u8; 15]; // Invalid size
			let wrapped_cek = [0u8; 40]; // Valid wrapped size

			let result = aes_key_unwrap(&wrapped_cek, &kek);
			assert!(result.is_err());
			assert!(matches!(result.unwrap_err(), HandshakeError::InvalidKeySize { .. }));
		}

		#[test]
		fn test_unwrap_invalid_wrapped_size() {
			let kek = [0u8; 32];
			let wrapped_cek = [0u8; 23]; // Not multiple of 8

			let result = aes_key_unwrap(&wrapped_cek, &kek);
			assert!(result.is_err());
			assert!(matches!(result.unwrap_err(), HandshakeError::InvalidKeySize { .. }));
		}

		#[test]
		fn test_unwrap_wrapped_too_small() {
			let kek = [0u8; 32];
			let wrapped_cek = [0u8; 16]; // Minimum is 24 bytes (IV + 16-byte key)

			let result = aes_key_unwrap(&wrapped_cek, &kek);
			assert!(result.is_err());
			assert!(matches!(result.unwrap_err(), HandshakeError::InvalidKeySize { .. }));
		}

		#[test]
		fn test_unwrap_wrong_kek() {
			let kek = [0x00u8; 32];
			let wrong_kek = [0xFFu8; 32];
			let cek = [0x42u8; 32];

			// Wrap with correct KEK
			let wrapped = aes_key_wrap(&cek, &kek).expect("wrap should succeed");

			// Try to unwrap with wrong KEK - should fail
			let result = aes_key_unwrap(&wrapped, &wrong_kek);
			assert!(result.is_err());
		}

		#[test]
		fn test_roundtrip_different_key_sizes() {
			let cek = [0x42u8; 32];

			// AES-128
			let kek_128 = [0x11u8; 16];
			let wrapped_128 = aes_key_wrap(&cek, &kek_128).expect("AES-128 wrap should succeed");
			let unwrapped_128 = aes_key_unwrap(&wrapped_128, &kek_128).expect("AES-128 unwrap should succeed");
			assert_eq!(unwrapped_128, cek);

			// AES-192
			let kek_192 = [0x22u8; 24];
			let wrapped_192 = aes_key_wrap(&cek, &kek_192).expect("AES-192 wrap should succeed");
			let unwrapped_192 = aes_key_unwrap(&wrapped_192, &kek_192).expect("AES-192 unwrap should succeed");
			assert_eq!(unwrapped_192, cek);

			// AES-256
			let kek_256 = [0x33u8; 32];
			let wrapped_256 = aes_key_wrap(&cek, &kek_256).expect("AES-256 wrap should succeed");
			let unwrapped_256 = aes_key_unwrap(&wrapped_256, &kek_256).expect("AES-256 unwrap should succeed");
			assert_eq!(unwrapped_256, cek);
		}
	}
	#[cfg(all(
		feature = "builder",
		feature = "aead",
		feature = "secp256k1",
		feature = "kdf",
		feature = "sha3"
	))]
	mod builder {
		use super::*;
		use crate::random::{generate_nonce, OsRng};
		use der::asn1::ObjectIdentifier;
		use der::{Decode, Encode};
		use k256::SecretKey as K256SecretKey;
		use spki::SubjectPublicKeyInfoOwned;

		#[test]
		fn test_validation() {
			let builder = TightBeamKariBuilder::<k256::Secp256k1>::default();

			// Should fail validation with all None fields
			let result = builder.validate();
			assert!(result.is_err());
			assert_eq!(result.unwrap_err(), KariBuilderError::MissingSenderPrivateKey);
		}

		#[test]
		fn test_fluent_interface() {
			let sender_key = K256SecretKey::random(&mut OsRng);

			let builder = TightBeamKariBuilder::<k256::Secp256k1>::default()
				.with_sender_priv(sender_key.clone())
				.with_kdf_info(b"test-info");

			// Builder pattern should work
			assert!(builder.sender_priv.is_some());
			assert_eq!(builder.kdf_info, b"test-info");
		}

		#[test]
		fn test_build_complete_kari() -> Result<(), Box<dyn std::error::Error>> {
			// Generate sender and recipient key-pairs
			let sender_key = K256SecretKey::random(&mut OsRng);
			let sender_pubkey = sender_key.public_key();
			let sender_spki = SubjectPublicKeyInfoOwned::from_key(sender_pubkey)?;

			let recipient_key = K256SecretKey::random(&mut OsRng);
			let recipient_pubkey = recipient_key.public_key();

			// Create UKM (user keying material) - typically client_nonce || server_nonce
			let client_nonce = [0x01u8; 32];
			let server_nonce = [0x02u8; 32];
			let mut ukm_bytes = Vec::new();
			ukm_bytes.extend_from_slice(&client_nonce);
			ukm_bytes.extend_from_slice(&server_nonce);
			let ukm = UserKeyingMaterial::new(ukm_bytes)?;

			// Create recipient identifier (use IssuerAndSerialNumber)
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
				issuer: x509_cert::name::Name::default(),
				serial_number: x509_cert::serial_number::SerialNumber::new(&[0x01])?,
			});

			// Key encryption algorithm (id-aes256-wrap)
			let key_enc_alg = AlgorithmIdentifierOwned {
				oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"), // id-aes256-wrap
				parameters: None,
			};

			// Generate a CEK to wrap
			let cek = [0x42u8; 32]; // 256-bit CEK

			// Build KARI
			let mut builder = TightBeamKariBuilder::<k256::Secp256k1>::default()
				.with_sender_priv(sender_key)
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient_pubkey)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);

			let recipient_info = builder.build(&cek).map_err(|e| format!("build failed: {:?}", e))?;

			// Verify the result
			match recipient_info {
				RecipientInfo::Kari(kari) => {
					assert_eq!(kari.version, CmsVersion::V3);
					assert_eq!(kari.recipient_enc_keys.len(), 1);

					// Verify originator is set
					match kari.originator {
						OriginatorIdentifierOrKey::OriginatorKey(orig_key) => {
							// Verify it has the right algorithm OID (EC public key)
							assert_eq!(orig_key.algorithm.oid, ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"));
						}
						_ => panic!("Expected OriginatorKey"),
					}

					// Verify UKM is present
					assert!(kari.ukm.is_some());
					assert_eq!(kari.ukm.as_ref().unwrap().as_bytes().len(), 64);
					// Verify key encryption algorithm
					assert_eq!(kari.key_enc_alg.oid, ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"));
					// Verify encrypted key is present and longer than CEK (due to RFC 3394 wrapping)
					assert!(kari.recipient_enc_keys[0].enc_key.as_bytes().len() > cek.len());
				}
				_ => panic!("Expected Kari variant"),
			}
			Ok(())
		}

		#[test]
		fn test_kari_serialization() -> Result<(), Box<dyn std::error::Error>> {
			// Generate keys
			let sender_key = K256SecretKey::random(&mut OsRng);
			let sender_pubkey = sender_key.public_key();
			let sender_spki = SubjectPublicKeyInfoOwned::from_key(sender_pubkey)?;

			let recipient_key = K256SecretKey::random(&mut OsRng);
			let recipient_pubkey = recipient_key.public_key();

			// UKM with random bytes
			let ukm_bytes = generate_nonce::<64>(None)?;
			let ukm = UserKeyingMaterial::new(ukm_bytes.to_vec())?;

			// Recipient ID
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
				issuer: x509_cert::name::Name::default(),
				serial_number: x509_cert::serial_number::SerialNumber::new(&[0x01])?,
			});

			// Key encryption algorithm
			let key_enc_alg = AlgorithmIdentifierOwned {
				oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"),
				parameters: None,
			};

			// CEK
			let cek = [0x33u8; 32];

			// Build KARI
			let mut builder = TightBeamKariBuilder::<k256::Secp256k1>::default()
				.with_sender_priv(sender_key)
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient_pubkey)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);

			let recipient_info = builder.build(&cek).map_err(|e| format!("build failed: {:?}", e))?;

			// Serialize to DER
			let der_bytes = recipient_info.to_der()?;
			assert!(!der_bytes.is_empty());

			// Deserialize back
			let decoded = RecipientInfo::from_der(&der_bytes)?;

			// Verify round-trip
			match decoded {
				RecipientInfo::Kari(kari) => {
					assert_eq!(kari.version, CmsVersion::V3);
					assert!(kari.ukm.is_some());
					assert_eq!(kari.recipient_enc_keys.len(), 1);
				}
				_ => panic!("Expected Kari variant after deserialization"),
			}
			Ok(())
		}
	}
}
