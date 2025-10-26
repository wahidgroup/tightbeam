//! ECIES (Elliptic Curve Integrated Encryption Scheme) implementation
//!
//! This module provides a generic, trait-based ECIES implementation that can work
//! with multiple elliptic curves (secp256k1, curve25519, P-256, etc.).
//!
//! # Architecture
//!
//! The implementation is split into:
//! - Generic traits for ECIES key operations
//! - Concrete implementations for specific curves (currently secp256k1)
//! - Curve-agnostic encryption/decryption functions
//!
//! # ECIES Protocol
//!
//! **Encryption:**
//! 1. Generate ephemeral keypair (r, R = r·G)
//! 2. Compute shared secret: S = r·P (where P is recipient's public key)
//! 3. Derive key: k_enc = KDF(C0, S) where C0 is ephemeral pubkey
//! 4. Encrypt: c = AEAD.Encrypt(k_enc, plaintext) with a random nonce
//! 5. Output: [R || nonce || ciphertext || tag]
//!
//! **Decryption:**
//! 1. Parse [R || nonce || ciphertext || tag] from ciphertext
//! 2. Compute shared secret: S = d·R (where d is recipient's private key)
//! 3. Derive key: k_enc = KDF(C0, S)
//! 4. Decrypt: plaintext = AEAD.Decrypt(k_enc, nonce, ciphertext, tag)

use rand_core::{CryptoRng, CryptoRngCore, OsRng, RngCore};

use crate::asn1::ObjectIdentifier;
use crate::crypto::aead::{Aead, Aes256Gcm, KeyInit, Payload};
use crate::crypto::kdf::{ecies_kdf, HkdfSha3_256, KdfError};
use crate::zeroize::Zeroizing;
use crate::ZeroizingBytes;

/// KDF info parameter for domain separation and protocol versioning
const ECIES_KDF_INFO: &[u8] = b"tightbeam-ecies-v1";

// ============================================================================
// Generic ECIES Traits
// ============================================================================

/// Trait for ECIES public keys with key exchange capability
pub trait EciesPublicKeyOps: Clone + PartialEq + Eq {
	/// Associated secret key type for this public key
	type SecretKey: EciesSecretKeyOps<PublicKey = Self>;

	/// The byte representation size for this public key
	const PUBLIC_KEY_SIZE: usize;

	/// Deserialize a public key from bytes
	fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self>
	where
		Self: Sized;

	/// Serialize the public key to bytes
	fn to_bytes(&self) -> Vec<u8>;
}

/// Trait for ECIES secret keys with key exchange and generation capability
pub trait EciesSecretKeyOps: Clone {
	/// Associated public key type
	type PublicKey: EciesPublicKeyOps;

	/// The byte representation size for this secret key
	const SECRET_KEY_SIZE: usize;

	/// Generate a new random secret key
	fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self;

	/// Deserialize a secret key from bytes
	fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self>
	where
		Self: Sized;

	/// Serialize the secret key to bytes (zeroizing)
	fn to_bytes(&self) -> ZeroizingBytes;

	/// Get the corresponding public key
	fn public_key(&self) -> Self::PublicKey;

	/// Perform ECDH key agreement with a public key, returning raw shared secret bytes
	fn diffie_hellman(&self, public_key: &Self::PublicKey) -> ZeroizingBytes;
}

/// Trait for ephemeral key generation in ECIES encryption
pub trait EciesEphemeral {
	/// Associated public key type
	type PublicKey: EciesPublicKeyOps;

	/// Generate a new ephemeral keypair and return (public_key_bytes, shared_secret_bytes)
	fn generate_ephemeral(
		recipient_pubkey: &Self::PublicKey,
		rng: &mut dyn rand_core::CryptoRngCore,
	) -> Result<(Vec<u8>, ZeroizingBytes)>;
}

// ============================================================================
// secp256k1 Implementation
// ============================================================================

use k256::{ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Errors specific to ECIES operations
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone)]
pub enum EciesError {
	/// Invalid public key
	#[cfg_attr(feature = "derive", error("Invalid ECIES public key"))]
	InvalidPublicKey,

	/// Invalid secret key
	#[cfg_attr(feature = "derive", error("Invalid ECIES secret key"))]
	InvalidSecretKey,

	/// Invalid ciphertext format
	#[cfg_attr(feature = "derive", error("Invalid ECIES ciphertext format"))]
	InvalidCiphertext,

	/// Encryption failed
	#[cfg_attr(feature = "derive", error("ECIES encryption failed"))]
	EncryptionFailed,

	/// Decryption failed
	#[cfg_attr(feature = "derive", error("ECIES decryption failed"))]
	DecryptionFailed,

	/// Key derivation failed
	#[cfg_attr(feature = "derive", error("ECIES key derivation failed: {0}"))]
	Kdf(#[cfg_attr(feature = "derive", from)] KdfError),
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for EciesError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			EciesError::InvalidPublicKey => write!(f, "Invalid ECIES public key"),
			EciesError::InvalidSecretKey => write!(f, "Invalid ECIES secret key"),
			EciesError::InvalidCiphertext => write!(f, "Invalid ECIES ciphertext format"),
			EciesError::EncryptionFailed => write!(f, "ECIES encryption failed"),
			EciesError::DecryptionFailed => write!(f, "ECIES decryption failed"),
			EciesError::Kdf(e) => write!(f, "ECIES key derivation failed: {}", e),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for EciesError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			EciesError::Kdf(e) => Some(e),
			_ => None,
		}
	}
}

/// A specialized Result type for ECIES operations
pub type Result<T> = core::result::Result<T, EciesError>;

impl From<KdfError> for EciesError {
	fn from(e: KdfError) -> Self {
		EciesError::Kdf(e)
	}
}

// ============================================================================
// Trait implementations for k256 types (secp256k1)
// ============================================================================

impl EciesPublicKeyOps for PublicKey {
	type SecretKey = SecretKey;

	const PUBLIC_KEY_SIZE: usize = 33;

	fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
		PublicKey::from_sec1_bytes(bytes.as_ref()).map_err(|_| EciesError::InvalidPublicKey)
	}

	fn to_bytes(&self) -> Vec<u8> {
		let point = self.to_encoded_point(true);
		point.as_bytes().to_vec()
	}
}

impl EciesSecretKeyOps for SecretKey {
	type PublicKey = PublicKey;

	const SECRET_KEY_SIZE: usize = 32;

	fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
		SecretKey::random(rng)
	}

	fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
		SecretKey::from_slice(bytes.as_ref()).map_err(|_| EciesError::InvalidSecretKey)
	}

	fn to_bytes(&self) -> ZeroizingBytes {
		Zeroizing::new(SecretKey::to_bytes(self).to_vec())
	}

	fn public_key(&self) -> Self::PublicKey {
		SecretKey::public_key(self)
	}

	fn diffie_hellman(&self, public_key: &Self::PublicKey) -> ZeroizingBytes {
		let shared_secret = k256::ecdh::diffie_hellman(self.to_nonzero_scalar(), public_key.as_affine());
		Zeroizing::new(shared_secret.raw_secret_bytes().to_vec())
	}
}

impl EciesEphemeral for SecretKey {
	type PublicKey = PublicKey;

	fn generate_ephemeral(
		recipient_pubkey: &Self::PublicKey,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(Vec<u8>, ZeroizingBytes)> {
		// Work around EphemeralSecret::random requiring Sized by using a wrapper
		// that converts the trait object to a concrete type call
		struct RngWrapper<'a>(&'a mut dyn CryptoRngCore);

		impl RngCore for RngWrapper<'_> {
			fn next_u32(&mut self) -> u32 {
				self.0.next_u32()
			}

			fn next_u64(&mut self) -> u64 {
				self.0.next_u64()
			}

			fn fill_bytes(&mut self, dest: &mut [u8]) {
				self.0.fill_bytes(dest)
			}

			fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
				self.0.try_fill_bytes(dest)
			}
		}

		impl CryptoRng for RngWrapper<'_> {}

		let mut wrapper = RngWrapper(rng);
		let ephemeral_secret = EphemeralSecret::random(&mut wrapper);
		let ephemeral_pubkey = ephemeral_secret.public_key();

		// Perform ECDH to get shared secret
		let shared_secret = ephemeral_secret.diffie_hellman(recipient_pubkey);

		let ephemeral_point = ephemeral_pubkey.to_encoded_point(true);
		let ephemeral_bytes = ephemeral_point.as_bytes().to_vec();
		let shared_bytes = Zeroizing::new(shared_secret.raw_secret_bytes().to_vec());
		Ok((ephemeral_bytes, shared_bytes))
	}
}

/// ECIES encrypted message format: [ephemeral_pubkey || nonce || ciphertext || tag]
///
/// The wire format consists of:
/// - `ephemeral_pubkey`: 33 bytes (compressed secp256k1 public key)
/// - `nonce`: 12 bytes (AES-GCM nonce)
/// - `ciphertext`: variable length (encrypted plaintext)
/// - `tag`: 16 bytes (AES-GCM authentication tag, appended to ciphertext)
pub struct EciesMessage {
	/// Ephemeral public key (serialized, 33 bytes for compressed secp256k1)
	pub ephemeral_pubkey: Vec<u8>,
	/// Nonce + encrypted data + authentication tag (12 + len(plaintext) + 16 bytes)
	pub ciphertext: Vec<u8>,
}

impl EciesMessage {
	/// Parse from wire format: [ephemeral_pubkey || ciphertext_with_tag]
	///
	/// For secp256k1, ephemeral_pubkey is 33 bytes (compressed SEC1)
	pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
		let bytes = bytes.as_ref();
		if bytes.len() < 33 + 12 + 16 {
			return Err(EciesError::InvalidCiphertext);
		}

		let ephemeral_pubkey = bytes[0..33].to_vec();
		let ciphertext = bytes[33..].to_vec();
		if ciphertext.len() < 12 + 16 {
			return Err(EciesError::InvalidCiphertext);
		}

		Ok(Self { ephemeral_pubkey, ciphertext })
	}

	/// Serialize to wire format: [ephemeral_pubkey || ciphertext_with_tag]
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(self.ephemeral_pubkey.len() + self.ciphertext.len());
		bytes.extend_from_slice(&self.ephemeral_pubkey);
		bytes.extend_from_slice(&self.ciphertext);
		bytes
	}
}

/// Encrypt plaintext using ECIES with recipient's public key
///
/// # Arguments
/// * `recipient_pubkey` - Recipient's public key (implements EciesPublicKeyOps)
/// * `plaintext` - Data to encrypt
/// * `associated_data` - Optional authenticated associated data (AAD)
/// * `rng` - Optional cryptographically secure random number generator (uses OsRng if not provided)
///
/// # Returns
/// Encrypted message containing ephemeral public key and ciphertext
///
/// # Type Parameters
/// * `PK` - Public key type implementing EciesPublicKeyOps
/// * `P` - Plaintext type that can be converted to bytes
/// * `R` - Random number generator type (optional, defaults to OsRng)
///
/// # Examples
///
/// ```ignore
/// // Using default OsRng
/// let encrypted = encrypt(&public_key, plaintext, None, None)?;
///
/// // Using custom RNG for testing
/// let mut rng = test_rng();
/// let encrypted = encrypt(&public_key, plaintext, None, Some(&mut rng))?;
/// ```
pub fn encrypt<PK, P, R>(
	recipient_pubkey: &PK,
	plaintext: P,
	associated_data: Option<&[u8]>,
	rng: Option<&mut R>,
) -> Result<EciesMessage>
where
	PK: EciesPublicKeyOps,
	PK::SecretKey: EciesEphemeral<PublicKey = PK>,
	P: AsRef<[u8]>,
	R: CryptoRng + RngCore,
{
	let plaintext = plaintext.as_ref();

	// Helper macro to avoid code duplication
	macro_rules! do_encrypt {
		($rng:expr) => {{
			// Use the trait method to generate ephemeral key and shared secret
			let (ephemeral_bytes, shared_secret) = PK::SecretKey::generate_ephemeral(recipient_pubkey, $rng)?;

			// Derive encryption key using KDF (includes C0 for non-malleability)
			let k_enc = ecies_kdf::<HkdfSha3_256>(&ephemeral_bytes, &shared_secret, ECIES_KDF_INFO, None)?;

			// Encrypt using AES-256-GCM
			let key = crate::crypto::utils::key_from_slice(&k_enc[..32]);
			let cipher = Aes256Gcm::new(&key);

			// Generate random nonce (96 bits for GCM)
			let mut nonce_bytes = [0u8; 12];
			$rng.fill_bytes(&mut nonce_bytes);
			let nonce = crate::crypto::utils::nonce_from_slice::<Aes256Gcm>(&nonce_bytes);

			// Prepare payload with optional AAD
			let payload = match associated_data {
				Some(aad) => Payload { msg: plaintext, aad },
				None => Payload { msg: plaintext, aad: b"" },
			};

			// Encrypt (produces ciphertext || tag)
			let mut ciphertext = cipher.encrypt(&nonce, payload).map_err(|_| EciesError::EncryptionFailed)?;

			// Prepend nonce to ciphertext (for transmission)
			let mut final_ciphertext = Vec::with_capacity(12 + ciphertext.len());
			final_ciphertext.extend_from_slice(&nonce_bytes);
			final_ciphertext.append(&mut ciphertext);

			Ok(EciesMessage { ephemeral_pubkey: ephemeral_bytes, ciphertext: final_ciphertext })
		}};
	}

	// Use provided RNG or default to OsRng
	match rng {
		Some(r) => do_encrypt!(r),
		None => do_encrypt!(&mut OsRng),
	}
}

pub fn decrypt<SK>(
	recipient_seckey: &SK,
	message: &EciesMessage,
	associated_data: Option<&[u8]>,
) -> Result<ZeroizingBytes>
where
	SK: EciesSecretKeyOps,
{
	// 1. Parse ephemeral public key
	let ephemeral_pubkey = <SK::PublicKey as EciesPublicKeyOps>::from_bytes(&message.ephemeral_pubkey)?;
	// 2. Perform ECDH to get shared secret
	let shared_secret = recipient_seckey.diffie_hellman(&ephemeral_pubkey);
	// 3. Derive encryption key using KDF (includes C0 for non-malleability)
	// Uses SHA3-256 with protocol versioning via info parameter
	// Derives 32-byte key for AES-256-GCM authenticated encryption
	let k_enc = ecies_kdf::<HkdfSha3_256>(&message.ephemeral_pubkey, &shared_secret, ECIES_KDF_INFO, None)?;
	// 4. Extract nonce and ciphertext
	if message.ciphertext.len() < 12 + 16 {
		return Err(EciesError::InvalidCiphertext);
	}
	let nonce = crate::crypto::utils::nonce_from_slice::<Aes256Gcm>(&message.ciphertext[0..12]);
	let ciphertext_with_tag = &message.ciphertext[12..];

	// 5. Decrypt using AES-256-GCM
	let key = crate::crypto::utils::key_from_slice(&k_enc[..32]);
	let cipher = Aes256Gcm::new(&key);

	// Prepare payload with optional AAD
	let payload = match associated_data {
		Some(aad) => Payload { msg: ciphertext_with_tag, aad },
		None => Payload { msg: ciphertext_with_tag, aad: b"" },
	};

	// Decrypt and verify tag
	let plaintext = cipher.decrypt(&nonce, payload).map_err(|_| EciesError::DecryptionFailed)?;

	Ok(Zeroizing::new(plaintext))
}

/// OID wrapper for ECIES with secp256k1
#[cfg(feature = "x509")]
pub struct EciesSecp256k1Oid;

#[cfg(feature = "x509")]
impl crate::der::oid::AssociatedOid for EciesSecp256k1Oid {
	const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.1.12.0");
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand_core::OsRng;

	// Helper to create a key pair
	fn keypair() -> (SecretKey, PublicKey) {
		let mut rng = OsRng;
		let secret = SecretKey::random(&mut rng);
		let public = secret.public_key();
		(secret, public)
	}

	// Helper for encryption roundtrip
	fn roundtrip(plaintext: &[u8], aad: Option<&[u8]>) -> Result<()> {
		let (secret, public) = keypair();
		let encrypted = encrypt(&public, plaintext, aad, None::<&mut OsRng>)?;
		let decrypted = decrypt(&secret, &encrypted, aad)?;
		assert_eq!(plaintext, &decrypted[..]);
		Ok(())
	}

	#[test]
	fn test_ecies_encryption() -> Result<()> {
		// Test cases: (plaintext, aad)
		let cases = [
			(&b"Hello, ECIES!"[..], None),
			(b"Secret message", Some(&b"authenticated data"[..])),
			(b"", None),
			// cspell:disable-next-line
			(b"The quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.", None),
			(b"\x00\x01\x02\x03\xFF\xFE\xFD\xFC", None),
			(b"Payload", Some(&b"version:1|timestamp:12345|nonce:abcdef"[..])),
		];

		for (plaintext, aad) in cases {
			roundtrip(plaintext, aad)?;
		}

		Ok(())
	}

	#[test]
	fn test_aad_validation() -> Result<()> {
		let mut rng = OsRng;
		let (secret, public) = keypair();
		let plaintext = b"Secret message";
		let correct_aad = b"authenticated data";

		// Test with explicit RNG to verify RNG parameter works
		let encrypted = encrypt(&public, plaintext, Some(correct_aad), Some(&mut rng))?;

		// Test cases: (aad, should_succeed)
		let cases = [
			(Some(&correct_aad[..]), true),
			(Some(&b"wrong data"[..]), false),
			(None, false),
			(Some(&b""[..]), false),
		];

		for (aad, should_succeed) in cases {
			let result = decrypt(&secret, &encrypted, aad);
			assert_eq!(result.is_ok(), should_succeed);
			if should_succeed {
				assert_eq!(&plaintext[..], &result?[..]);
			}
		}

		Ok(())
	}

	#[test]
	fn test_serialization() -> Result<()> {
		let (secret, public) = keypair();
		let plaintext = b"Test serialization";

		// Message serialization roundtrip
		let encrypted = encrypt(&public, plaintext, None, None::<&mut OsRng>)?;
		let bytes = encrypted.to_bytes();
		let parsed = EciesMessage::from_bytes(&bytes)?;
		let decrypted = decrypt(&secret, &parsed, None)?;
		assert_eq!(&plaintext[..], &decrypted[..]);

		// Key serialization roundtrip using traits
		let secret_bytes = <SecretKey as EciesSecretKeyOps>::to_bytes(&secret);
		let public_bytes = <PublicKey as EciesPublicKeyOps>::to_bytes(&public);

		let secret2 = <SecretKey as EciesSecretKeyOps>::from_bytes(&secret_bytes)?;
		let public2 = <PublicKey as EciesPublicKeyOps>::from_bytes(&public_bytes)?;

		assert_eq!(
			<PublicKey as EciesPublicKeyOps>::to_bytes(&public),
			<PublicKey as EciesPublicKeyOps>::to_bytes(&public2)
		);
		assert_eq!(
			<PublicKey as EciesPublicKeyOps>::to_bytes(&secret.public_key()),
			<PublicKey as EciesPublicKeyOps>::to_bytes(&secret2.public_key())
		);

		Ok(())
	}

	#[test]
	fn test_security_properties() -> Result<()> {
		let plaintext = b"Sensitive data";

		// Wrong recipient cannot decrypt
		let (_, public1) = keypair();
		let (secret2, _) = keypair();

		let encrypted = encrypt(&public1, plaintext, None, None::<&mut OsRng>)?;
		let result = decrypt(&secret2, &encrypted, None);

		if let Ok(decrypted) = result {
			assert_ne!(&plaintext[..], &decrypted[..]);
		}

		// Tampered ciphertext should fail authentication
		let (secret, public) = keypair();

		let tamper_functions: [fn(&mut EciesMessage); 4] = [
			|msg| {
				if let Some(byte) = msg.ciphertext.last_mut() {
					*byte ^= 0xFF;
				}
			},
			|msg| {
				if let Some(byte) = msg.ciphertext.first_mut() {
					*byte ^= 0xFF;
				}
			},
			|msg| {
				msg.ciphertext.truncate(msg.ciphertext.len().saturating_sub(1));
			},
			|msg| {
				if let Some(byte) = msg.ephemeral_pubkey.first_mut() {
					*byte ^= 0xFF;
				}
			},
		];

		for tamper_fn in tamper_functions {
			let mut encrypted = encrypt(&public, plaintext, None, None::<&mut OsRng>)?;
			tamper_fn(&mut encrypted);
			assert!(decrypt(&secret, &encrypted, None).is_err());
		}

		Ok(())
	}

	#[test]
	fn test_edge_cases() -> Result<()> {
		// Invalid ciphertext formats
		let invalid_ciphertexts = [
			vec![],
			vec![0u8; 32],
			vec![0u8; 33], // Missing ciphertext
			vec![0u8; 45], // 33 + 12 (less than min 33+16)
		];

		for data in invalid_ciphertexts {
			assert!(EciesMessage::from_bytes(&data).is_err());
		}

		// Invalid key formats
		assert!(<PublicKey as EciesPublicKeyOps>::from_bytes([0xFFu8; 33]).is_err());
		assert!(<SecretKey as EciesSecretKeyOps>::from_bytes([0x00u8; 32]).is_err());

		Ok(())
	}
}
