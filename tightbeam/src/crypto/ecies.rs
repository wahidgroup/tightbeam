//! ECIES (Elliptic Curve Integrated Encryption Scheme) implementation
//!
//! This module provides a generic, trait-based ECIES implementation that can
//! work with multiple elliptic curves (secp256k1, curve25519, P-256, etc.).
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
//!
//! # Security
//!
//! This implementation uses constant-time cryptographic primitives
//! - ECDH operations (k256): constant-time scalar multiplication
//! - AES-256-GCM: constant-time encryption and tag verification  
//! - HKDF-SHA3-256: constant-time key derivation

use rand_core::{CryptoRng, CryptoRngCore, OsRng, RngCore};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::asn1::ObjectIdentifier;
use crate::constants::{AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE, EC_PUBKEY_COMPRESSED_SIZE, TIGHTBEAM_ECIES_KDF_INFO};
use crate::der::oid::AssociatedOid;

use crate::crypto::aead::{Aead, AeadCore, Aes256Gcm, Key, KeyInit, Nonce, Payload};
use crate::crypto::common::{typenum::Unsigned, KeySizeUser};
use crate::crypto::kdf::{ecies_kdf, HkdfSha3_256, KdfError, KdfFunction};
use crate::crypto::secret::{Secret, SecretSlice};
use crate::crypto::sign::ecdsa::k256::ecdh::EphemeralSecret;
use crate::crypto::sign::ecdsa::k256::elliptic_curve::sec1::ToEncodedPoint;
use crate::crypto::sign::ecdsa::k256::{PublicKey, SecretKey};
use crate::random::RngWrapper;

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

	/// Get the corresponding public key
	fn public_key(&self) -> Self::PublicKey;

	/// Perform ECDH key agreement with a public key, returning raw shared secret bytes
	fn diffie_hellman(&self, public_key: &Self::PublicKey) -> SecretSlice<u8>;
}

/// Trait for ephemeral key generation in ECIES encryption
pub trait EciesEphemeral {
	/// Associated public key type
	type PublicKey: EciesPublicKeyOps;

	/// Generate a new ephemeral keypair and return (public_key_bytes, shared_secret_bytes)
	fn generate_ephemeral(
		recipient_pubkey: &Self::PublicKey,
		rng: &mut dyn rand_core::CryptoRngCore,
	) -> Result<(Vec<u8>, SecretSlice<u8>)>;
}

// ============================================================================
// secp256k1 Implementation
// ============================================================================

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Errors specific to ECIES operations
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone)]
pub enum EciesError {
	/// Invalid ciphertext format
	#[cfg_attr(feature = "derive", error("Invalid ECIES ciphertext format"))]
	InvalidCiphertext,

	/// Invalid public key
	#[cfg_attr(feature = "derive", error("Invalid ECIES public key: {0}"))]
	InvalidPublicKey(crate::crypto::sign::ecdsa::k256::elliptic_curve::Error),

	/// Invalid secret key
	#[cfg_attr(feature = "derive", error("Invalid ECIES secret key: {0}"))]
	InvalidSecretKey(crate::crypto::sign::ecdsa::k256::elliptic_curve::Error),

	/// Encryption failed
	#[cfg_attr(feature = "derive", error("ECIES encryption failed: {0}"))]
	EncryptionFailed(crate::crypto::aead::Error),

	/// Decryption failed
	#[cfg_attr(feature = "derive", error("ECIES decryption failed: {0}"))]
	DecryptionFailed(crate::crypto::aead::Error),

	/// Key derivation failed
	#[cfg_attr(feature = "derive", error("ECIES key derivation failed: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	Kdf(#[cfg_attr(feature = "derive", from)] KdfError),

	/// Secret material was unavailable
	#[cfg_attr(feature = "derive", error("Secret unavailable: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SecretUnavailable(crate::crypto::secret::SecretError),
}

crate::impl_error_display!(EciesError {
	InvalidCiphertext => "Invalid ECIES ciphertext format",
	InvalidPublicKey(e) => "Invalid ECIES public key: {e}",
	InvalidSecretKey(e) => "Invalid ECIES secret key: {e}",
	EncryptionFailed(e) => "ECIES encryption failed: {e}",
	DecryptionFailed(e) => "ECIES decryption failed: {e}",
	Kdf(e) => "ECIES key derivation failed: {e}",
	SecretUnavailable(e) => "Secret unavailable: {e}",
});

#[cfg(not(feature = "derive"))]
crate::impl_from!(crate::crypto::secret::SecretError => EciesError::SecretUnavailable);

/// A specialized Result type for ECIES operations
pub type Result<T> = core::result::Result<T, EciesError>;

// ============================================================================
// Trait implementations for k256 types (secp256k1)
// ============================================================================

impl EciesPublicKeyOps for PublicKey {
	type SecretKey = SecretKey;

	const PUBLIC_KEY_SIZE: usize = EC_PUBKEY_COMPRESSED_SIZE;

	fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
		PublicKey::from_sec1_bytes(bytes.as_ref()).map_err(EciesError::InvalidPublicKey)
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

	fn public_key(&self) -> Self::PublicKey {
		SecretKey::public_key(self)
	}

	fn diffie_hellman(&self, public_key: &Self::PublicKey) -> SecretSlice<u8> {
		let shared_secret = k256::ecdh::diffie_hellman(self.to_nonzero_scalar(), public_key.as_affine());
		let v = shared_secret.raw_secret_bytes().to_vec().into_boxed_slice();
		Secret::from(v)
	}
}

impl core::convert::TryFrom<SecretSlice<u8>> for SecretKey {
	type Error = EciesError;
	fn try_from(bytes: SecretSlice<u8>) -> Result<Self> {
		use crate::crypto::secret::ToInsecure;
		let raw = bytes.to_insecure().map_err(EciesError::from)?;
		SecretKey::from_slice(&raw).map_err(EciesError::InvalidSecretKey)
	}
}

impl From<&SecretKey> for SecretSlice<u8> {
	fn from(sk: &SecretKey) -> Self {
		let v = SecretKey::to_bytes(sk).to_vec();
		Secret::from(v.into_boxed_slice())
	}
}

impl EciesEphemeral for SecretKey {
	type PublicKey = PublicKey;

	fn generate_ephemeral(
		recipient_pubkey: &Self::PublicKey,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(Vec<u8>, SecretSlice<u8>)> {
		let mut wrapper = RngWrapper(rng);
		let ephemeral_secret = EphemeralSecret::random(&mut wrapper);
		let ephemeral_pubkey = ephemeral_secret.public_key();

		// Perform ECDH to get shared secret
		let shared_secret = ephemeral_secret.diffie_hellman(recipient_pubkey);

		let ephemeral_point = ephemeral_pubkey.to_encoded_point(true);
		let ephemeral_bytes = ephemeral_point.as_bytes().to_vec();
		let shared_bytes = Secret::from(shared_secret.raw_secret_bytes().to_vec().into_boxed_slice());
		Ok((ephemeral_bytes, shared_bytes))
	}
}

/// Trait for ECIES encrypted messages with curve-specific sizes
pub trait EciesMessageOps: Sized {
	/// Size of the ephemeral public key in bytes (curve-specific)
	const PUBKEY_SIZE: usize;

	/// Parse from wire format: [ephemeral_pubkey || ciphertext_with_tag]
	fn from_bytes(bytes: &[u8]) -> Result<Self>;

	/// Serialize to wire format: [ephemeral_pubkey || ciphertext_with_tag]
	fn to_bytes(&self) -> Vec<u8>;

	/// Get ephemeral public key bytes
	fn ephemeral_pubkey(&self) -> &[u8];

	/// Get ciphertext bytes (nonce || encrypted_data || tag)
	fn ciphertext(&self) -> &[u8];
}

/// ECIES encrypted message for secp256k1 curve
///
/// The wire format consists of:
/// - `ephemeral_pubkey`: 33 bytes (compressed secp256k1 public key)
/// - `nonce`: 12 bytes (AES-GCM nonce)
/// - `ciphertext`: variable length (encrypted plaintext)
/// - `tag`: 16 bytes (AES-GCM authentication tag, appended to ciphertext)
pub struct Secp256k1EciesMessage {
	/// Ephemeral public key (serialized, compressed SEC1 format)
	ephemeral_pubkey: Vec<u8>,
	/// Nonce + encrypted data + authentication tag
	ciphertext: Vec<u8>,
}

impl Secp256k1EciesMessage {
	/// Minimum ciphertext size (nonce + tag)
	const MIN_CIPHERTEXT_SIZE: usize = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;

	/// Parse from wire format: [ephemeral_pubkey || ciphertext_with_tag]
	pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
		let bytes = bytes.as_ref();
		if bytes.len() < EC_PUBKEY_COMPRESSED_SIZE + Self::MIN_CIPHERTEXT_SIZE {
			return Err(EciesError::InvalidCiphertext);
		}

		let ephemeral_pubkey = bytes[0..EC_PUBKEY_COMPRESSED_SIZE].to_vec();
		let ciphertext = bytes[EC_PUBKEY_COMPRESSED_SIZE..].to_vec();
		if ciphertext.len() < Self::MIN_CIPHERTEXT_SIZE {
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

	/// Mutable access to ephemeral public key bytes (for tampering tests)
	#[cfg(test)]
	pub(crate) fn ephemeral_pubkey_mut(&mut self) -> &mut Vec<u8> {
		&mut self.ephemeral_pubkey
	}

	/// Mutable access to ciphertext bytes (for tampering tests)
	#[cfg(test)]
	pub(crate) fn ciphertext_mut(&mut self) -> &mut Vec<u8> {
		&mut self.ciphertext
	}
}

impl EciesMessageOps for Secp256k1EciesMessage {
	const PUBKEY_SIZE: usize = EC_PUBKEY_COMPRESSED_SIZE;

	fn from_bytes(bytes: &[u8]) -> Result<Self> {
		Self::from_bytes(bytes)
	}

	fn to_bytes(&self) -> Vec<u8> {
		Self::to_bytes(self)
	}

	fn ephemeral_pubkey(&self) -> &[u8] {
		&self.ephemeral_pubkey
	}

	fn ciphertext(&self) -> &[u8] {
		&self.ciphertext
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
/// * `M` - Message type implementing EciesMessageOps
/// * `K` - KDF used to derive the content-encryption key
/// * `A` - AEAD cipher used to seal the plaintext
pub fn encrypt<PK, P, R, M, K, A>(
	recipient_pubkey: &PK,
	plaintext: P,
	associated_data: Option<&[u8]>,
	rng: Option<&mut R>,
) -> Result<M>
where
	PK: EciesPublicKeyOps,
	PK::SecretKey: EciesEphemeral<PublicKey = PK>,
	P: AsRef<[u8]>,
	R: CryptoRng + RngCore,
	M: EciesMessageOps,
	K: KdfFunction,
	A: Aead + KeyInit,
{
	let plaintext = plaintext.as_ref();
	let key_size = <A as KeySizeUser>::KeySize::USIZE;

	// Helper macro to avoid code duplication
	macro_rules! do_encrypt {
		($rng:expr) => {{
			// Use the trait method to generate ephemeral key and shared secret
			let (ephemeral_bytes, shared_secret) = PK::SecretKey::generate_ephemeral(recipient_pubkey, $rng)?;

			// Derive encryption key using the negotiated KDF (binds C0 for non-malleability).
			let k_enc = ecies_kdf::<K>(&ephemeral_bytes, shared_secret, TIGHTBEAM_ECIES_KDF_INFO, None)?;

			// Build the negotiated AEAD cipher from the derived key material.
			let key = Key::<A>::from_slice(&k_enc[..key_size]);
			let cipher = A::new(key);

			// Generate a random nonce sized for the negotiated cipher.
			let mut nonce = Nonce::<A>::default();
			$rng.fill_bytes(nonce.as_mut_slice());

			// Prepare payload with optional AAD
			let payload = match associated_data {
				Some(aad) => Payload { msg: plaintext, aad },
				None => Payload { msg: plaintext, aad: b"" },
			};

			// Encrypt and prepend nonce in a single allocation
			let ciphertext = cipher.encrypt(&nonce, payload).map_err(EciesError::EncryptionFailed)?;
			let encrypted_len = ciphertext.len();
			let mut final_ciphertext = Vec::with_capacity(nonce.len() + encrypted_len);
			final_ciphertext.extend_from_slice(nonce.as_slice());
			final_ciphertext.extend_from_slice(&ciphertext);

			// Construct message from concatenated bytes (avoid extra allocation)
			let total_len = ephemeral_bytes.len() + final_ciphertext.len();
			let mut wire_bytes = Vec::with_capacity(total_len);
			wire_bytes.extend_from_slice(&ephemeral_bytes);
			wire_bytes.extend_from_slice(&final_ciphertext);
			M::from_bytes(&wire_bytes)
		}};
	}

	// Use provided RNG or default to OsRng
	match rng {
		Some(r) => do_encrypt!(r),
		None => do_encrypt!(&mut OsRng),
	}
}

pub fn decrypt<SK, M, K, A>(
	recipient_seckey: &SK,
	message: &M,
	associated_data: Option<&[u8]>,
) -> Result<SecretSlice<u8>>
where
	SK: EciesSecretKeyOps,
	M: EciesMessageOps,
	K: KdfFunction,
	A: Aead + KeyInit,
{
	// Compute the shared secret S = d·R, then derive the key and open.
	let ephemeral_pubkey = <SK::PublicKey as EciesPublicKeyOps>::from_bytes(message.ephemeral_pubkey())?;
	let shared_secret = recipient_seckey.diffie_hellman(&ephemeral_pubkey);
	decrypt_with_shared_secret::<M, K, A>(message, shared_secret, associated_data)
}

/// Decrypt an ECIES message from a precomputed ECDH shared secret.
///
/// Splits the `d·R` step out of [`decrypt`] so the recipient private key can
/// live behind an external boundary (HSM, KMS, secure enclave). Callers obtain
/// the shared secret out-of-band (e.g. `SigningKeyProvider::key_agreement`) and
/// pass it here for key derivation and AEAD opening.
pub fn decrypt_with_shared_secret<M, K, A>(
	message: &M,
	shared_secret: SecretSlice<u8>,
	associated_data: Option<&[u8]>,
) -> Result<SecretSlice<u8>>
where
	M: EciesMessageOps,
	K: KdfFunction,
	A: Aead + KeyInit,
{
	// Derive encryption key using the negotiated KDF (binds C0 for non-malleability).
	let k_enc = ecies_kdf::<K>(message.ephemeral_pubkey(), shared_secret, TIGHTBEAM_ECIES_KDF_INFO, None)?;

	// AEAD geometry comes from the negotiated cipher, not literals.
	let nonce_size = <A as AeadCore>::NonceSize::USIZE;
	let tag_size = <A as AeadCore>::TagSize::USIZE;
	let key_size = <A as KeySizeUser>::KeySize::USIZE;

	let ciphertext_bytes = message.ciphertext();
	if ciphertext_bytes.len() < nonce_size + tag_size {
		return Err(EciesError::InvalidCiphertext);
	}

	let nonce = Nonce::<A>::from_slice(&ciphertext_bytes[..nonce_size]);
	let ciphertext_with_tag = &ciphertext_bytes[nonce_size..];

	// Build the negotiated AEAD cipher from the derived key material.
	let key = Key::<A>::from_slice(&k_enc[..key_size]);
	let cipher = A::new(key);

	// Prepare payload with optional AAD
	let payload = match associated_data {
		Some(aad) => Payload { msg: ciphertext_with_tag, aad },
		None => Payload { msg: ciphertext_with_tag, aad: b"" },
	};

	// Decrypt and verify tag
	let plaintext = cipher.decrypt(nonce, payload).map_err(EciesError::DecryptionFailed)?;
	Ok(Secret::from(plaintext.into_boxed_slice()))
}

/// Borrow the ephemeral public key from raw ECIES wire bytes without copying.
pub fn ephemeral_pubkey_bytes<M>(bytes: &[u8]) -> Result<&[u8]>
where
	M: EciesMessageOps,
{
	bytes.get(..M::PUBKEY_SIZE).ok_or(EciesError::InvalidCiphertext)
}

#[cfg(feature = "x509")]
crate::define_oid_wrapper!(
	/// OID wrapper for ECIES with secp256k1
	EciesSecp256k1Oid,
	"1.3.132.1.12.0"
);

// ============================================================================
// Encryptor/Decryptor Trait Implementations
// ============================================================================

/// ECIES encryptor - encrypts messages to a recipient's public key.
///
/// This type implements the `Encryptor` trait, allowing it to be used
/// with `FrameBuilder::with_encryptor()` for asymmetric message encryption.
///
/// # Example
/// ```ignore
/// let encryptor = EciesEncryptor::new(recipient_pubkey);
/// let frame = compose! {
///     V2: id: b"msg-001",
///         message: payload,
///         encryptor<EciesSecp256k1Oid, _>: encryptor
/// }?;
/// ```
#[cfg(feature = "x509")]
pub struct EciesEncryptor {
	recipient_pubkey: PublicKey,
}

#[cfg(feature = "x509")]
impl EciesEncryptor {
	/// Create a new ECIES encryptor for the given recipient's public key.
	pub fn new(recipient_pubkey: PublicKey) -> Self {
		Self { recipient_pubkey }
	}

	/// Create from raw public key bytes (SEC1 format).
	pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
		let pubkey = PublicKey::from_bytes(bytes)?;
		Ok(Self::new(pubkey))
	}
}

#[cfg(feature = "x509")]
impl crate::crypto::aead::Encryptor<EciesSecp256k1Oid> for EciesEncryptor {
	fn encrypt_content(
		&self,
		data: impl AsRef<[u8]>,
		_nonce: impl AsRef<[u8]>, // Ignored - ECIES generates its own nonce
		content_type: Option<ObjectIdentifier>,
	) -> crate::error::Result<crate::EncryptedContentInfo> {
		// Use existing ECIES encrypt function with the secp256k1 suite.
		let ecies_msg = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
			&self.recipient_pubkey,
			data.as_ref(),
			None,
			None::<&mut OsRng>,
		)?;

		// Store the full ECIES message (ephemeral pubkey + ciphertext) as encrypted content
		let encrypted_bytes = ecies_msg.to_bytes();
		let content_type = content_type.unwrap_or(crate::oids::DATA);

		// No nonce parameter needed - ECIES embeds the ephemeral pubkey
		let content_enc_alg = crate::AlgorithmIdentifier { oid: EciesSecp256k1Oid::OID, parameters: None };
		let encrypted_content = Some(crate::der::asn1::OctetString::new(encrypted_bytes)?);

		Ok(crate::EncryptedContentInfo { content_type, content_enc_alg, encrypted_content })
	}
}

/// ECIES decryptor - decrypts messages with recipient's secret key.
///
/// This type implements the `Decryptor` trait for decrypting ECIES-encrypted
/// messages.
///
/// # Example
/// ```ignore
/// let decryptor = EciesDecryptor::new(my_secret_key);
/// let plaintext = frame.decrypt(&decryptor)?;
/// ```
#[cfg(feature = "x509")]
pub struct EciesDecryptor {
	secret_key: SecretKey,
}

#[cfg(feature = "x509")]
impl EciesDecryptor {
	/// Create a new ECIES decryptor with the given secret key.
	pub fn new(secret_key: SecretKey) -> Self {
		Self { secret_key }
	}
}

#[cfg(feature = "x509")]
impl crate::crypto::aead::Decryptor for EciesDecryptor {
	fn decrypt_content(&self, info: &crate::EncryptedContentInfo) -> crate::error::Result<Vec<u8>> {
		// Extract the encrypted bytes
		let encrypted_bytes = info
			.encrypted_content
			.as_ref()
			.ok_or(crate::TightBeamError::MissingEncryptionInfo)?
			.as_bytes();

		// Parse as ECIES message
		let ecies_msg = Secp256k1EciesMessage::from_bytes(encrypted_bytes)?;
		// Decrypt using the secp256k1 ECIES suite.
		let plaintext = decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(&self.secret_key, &ecies_msg, None)?;

		// Convert SecretSlice to Vec<u8>
		use crate::crypto::secret::ToInsecure;
		Ok(plaintext.to_insecure()?.to_vec())
	}
}

/// ECIES decryptor driven by a precomputed ECDH shared secret.
///
/// Pairs with [`ephemeral_pubkey_bytes`] and an async key-agreement backend
/// (`SigningKeyProvider::key_agreement`) so the recipient private key can stay
/// inside an HSM/KMS/secure enclave.
#[cfg(all(
	feature = "digest",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
pub struct EciesSharedSecretDecryptor<P> {
	shared_secret: SecretSlice<u8>,
	_provider: core::marker::PhantomData<P>,
}

#[cfg(all(
	feature = "digest",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
impl<P> EciesSharedSecretDecryptor<P> {
	/// Build a decryptor from a precomputed ECDH shared secret.
	pub fn new(shared_secret: impl Into<SecretSlice<u8>>) -> Self {
		Self { shared_secret: shared_secret.into(), _provider: core::marker::PhantomData }
	}
}

#[cfg(all(
	feature = "digest",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
impl<P> crate::crypto::aead::Decryptor for EciesSharedSecretDecryptor<P>
where
	P: crate::crypto::profiles::CryptoProvider,
	P::AeadCipher: KeyInit,
{
	fn decrypt_content(&self, info: &crate::EncryptedContentInfo) -> crate::error::Result<Vec<u8>> {
		use crate::crypto::secret::ToInsecure;

		let encrypted_bytes = info
			.encrypted_content
			.as_ref()
			.ok_or(crate::TightBeamError::MissingEncryptionInfo)?
			.as_bytes();

		let ecies_msg = <P::EciesMessage as EciesMessageOps>::from_bytes(encrypted_bytes)?;
		let shared_secret = self.shared_secret.with(|bytes| SecretSlice::from(bytes.to_vec()))?;
		let plaintext =
			decrypt_with_shared_secret::<P::EciesMessage, P::Kdf, P::AeadCipher>(&ecies_msg, shared_secret, None)?;

		Ok(plaintext.to_insecure()?.to_vec())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::secret::ToInsecure;
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
		let encrypted = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
			&public,
			plaintext,
			aad,
			None::<&mut OsRng>,
		)?;
		let decrypted = decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(&secret, &encrypted, aad)?;
		assert_eq!(plaintext, &decrypted.to_insecure().map_err(EciesError::from)?[..]);
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
		let encrypted = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
			&public,
			plaintext,
			Some(correct_aad),
			Some(&mut rng),
		)?;
		// Test cases: (aad, should_succeed)
		let cases = [
			(Some(&correct_aad[..]), true),
			(Some(&b"wrong data"[..]), false),
			(None, false),
			(Some(&b""[..]), false),
		];

		for (aad, should_succeed) in cases {
			let result = decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(&secret, &encrypted, aad);
			assert_eq!(result.is_ok(), should_succeed);
			if should_succeed {
				assert_eq!(&plaintext[..], &result?.to_insecure().map_err(EciesError::from)?[..]);
			}
		}

		Ok(())
	}

	#[test]
	fn test_serialization() -> Result<()> {
		let (secret, public) = keypair();
		let plaintext = b"Test serialization";

		// Message serialization roundtrip
		let encrypted = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
			&public,
			plaintext,
			None,
			None::<&mut OsRng>,
		)?;
		let bytes = encrypted.to_bytes();
		let parsed = Secp256k1EciesMessage::from_bytes(&bytes)?;
		let decrypted = decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(&secret, &parsed, None)?;
		assert_eq!(&plaintext[..], &decrypted.to_insecure().map_err(EciesError::from)?[..]);

		// Key serialization roundtrip using traits
		let secret_bytes: SecretSlice<u8> = (&secret).into();
		let public_bytes = public.to_bytes();

		let secret2 = SecretKey::try_from(secret_bytes)?;
		let public2 = PublicKey::from_bytes(&public_bytes)?;

		assert_eq!(public.to_bytes(), public2.to_bytes());
		assert_eq!(secret.public_key().to_bytes(), secret2.public_key().to_bytes());

		Ok(())
	}

	#[test]
	fn test_security_properties() -> Result<()> {
		let plaintext = b"Sensitive data";

		// Wrong recipient cannot decrypt
		let (_, public1) = keypair();
		let (secret2, _) = keypair();

		let encrypted = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
			&public1,
			plaintext,
			None,
			None::<&mut OsRng>,
		)?;
		// Wrong recipient derives a different ECDH shared secret, so AEAD tag verification must fail.
		assert!(decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(&secret2, &encrypted, None).is_err());

		// Tampered ciphertext should fail authentication
		let (secret, public) = keypair();

		let tamper_functions: [fn(&mut Secp256k1EciesMessage); 4] = [
			|msg| {
				if let Some(byte) = msg.ciphertext_mut().last_mut() {
					*byte ^= 0xFF;
				}
			},
			|msg| {
				if let Some(byte) = msg.ciphertext_mut().first_mut() {
					*byte ^= 0xFF;
				}
			},
			|msg| {
				let len = msg.ciphertext_mut().len().saturating_sub(1);
				msg.ciphertext_mut().truncate(len);
			},
			|msg| {
				if let Some(byte) = msg.ephemeral_pubkey_mut().first_mut() {
					*byte ^= 0xFF;
				}
			},
		];

		for tamper_fn in tamper_functions {
			let mut encrypted = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
				&public,
				plaintext,
				None,
				None::<&mut OsRng>,
			)?;
			tamper_fn(&mut encrypted);
			assert!(decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(&secret, &encrypted, None).is_err());
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
			assert!(Secp256k1EciesMessage::from_bytes(&data).is_err());
		}

		// Invalid key formats
		assert!(PublicKey::from_bytes([0xFFu8; 33]).is_err());
		assert!(SecretKey::try_from(Secret::from(vec![0x00u8; 32].into_boxed_slice())).is_err());

		Ok(())
	}

	/// Decrypt an ECIES payload with the recipient private key held behind a
	/// `SigningKeyProvider`: the `d·R` step runs via `key_agreement`, then the
	/// shared-secret decryptor opens it through the standard `Decryptor` seam.
	#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh", feature = "tokio"))]
	#[tokio::test]
	async fn shared_secret_decryptor_via_provider() -> crate::error::Result<()> {
		use crate::crypto::aead::{Decryptor, Encryptor};
		use crate::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::sign::ecdsa::Secp256k1SigningKey;

		let plaintext = b"hsm-backed ecies decryption";
		let (secret, public) = keypair();

		// Sender encrypts to the recipient public key (in-memory Encryptor seam).
		let info = EciesEncryptor::new(public).encrypt_content(plaintext, [], None)?;
		let wire = info.encrypted_content.as_ref().ok_or(EciesError::InvalidCiphertext)?.as_bytes();

		// Recipient: borrow the ephemeral pubkey, run d·R behind the provider.
		let epk = ephemeral_pubkey_bytes::<Secp256k1EciesMessage>(wire)?;
		let provider = Secp256k1KeyProvider::from(Secp256k1SigningKey::from(secret));
		let shared = provider.key_agreement(epk).await?;

		// Open via the standard Decryptor seam (what Frame::decrypt_bytes calls).
		let decryptor = EciesSharedSecretDecryptor::<DefaultCryptoProvider>::new(shared);
		let opened = decryptor.decrypt_content(&info)?;

		assert_eq!(
			opened.as_slice(),
			plaintext,
			"provider key agreement must reproduce the ECIES plaintext"
		);
		Ok(())
	}
}
