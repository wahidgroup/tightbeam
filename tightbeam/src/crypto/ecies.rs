//! ECIES (Elliptic Curve Integrated Encryption Scheme).
//!
//! This module provides a generic, trait-based ECIES implementation for
//! multiple elliptic curves, such as secp256k1, curve25519, and P-256.
//!
//! # Architecture
//!
//! - Generic traits define the ECIES key operations.
//! - Concrete implementations cover specific curves, currently secp256k1.
//! - The encryption and decryption functions are curve-agnostic.
//!
//! # ECIES Protocol
//!
//! **Encryption:**
//!
//! 1. Generate an ephemeral keypair (r, R = r·G).
//! 2. Compute the shared secret S = r·P, where P is the recipient public key.
//! 3. Derive the key k_enc = KDF(C0, S), where C0 is the ephemeral public key.
//! 4. Encrypt c = AEAD.Encrypt(k_enc, plaintext) under a random nonce.
//! 5. Output `R || nonce || ciphertext || tag`.
//!
//! **Decryption:**
//!
//! 1. Parse `R || nonce || ciphertext || tag` from the ciphertext.
//! 2. Compute the shared secret S = d·R, where d is the recipient private key.
//! 3. Derive the key k_enc = KDF(C0, S).
//! 4. Decrypt plaintext = AEAD.Decrypt(k_enc, nonce, ciphertext, tag).
//!
//! # Security
//!
//! The underlying primitives are constant-time:
//!
//! - ECDH in k256 uses constant-time scalar multiplication.
//! - AES-256-GCM encrypts and verifies the tag in constant time.
//! - HKDF-SHA3-256 derives keys in constant time.

use rand_core::{CryptoRng, CryptoRngCore, OsRng, RngCore};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::constants::{
	AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE, ECDH_SHARED_SECRET_SIZE, EC_PUBKEY_COMPRESSED_SIZE, TIGHTBEAM_ECIES_KDF_INFO,
};
use crate::crypto::aead::{Aead, AeadCore, KeyInit, Nonce, Payload};
use crate::crypto::common::{typenum::Unsigned, KeySizeUser};
use crate::crypto::hkdf::InvalidLength;
use crate::crypto::k256::ecdh::{diffie_hellman, EphemeralSecret};
use crate::crypto::k256::elliptic_curve::sec1::ToEncodedPoint;
use crate::crypto::k256::{PublicKey, SecretKey};
use crate::crypto::kdf::{EcdhSecret, EciesKdf, KdfError, KdfFunction};
use crate::crypto::secret::{Secret, SecretSlice};
use crate::random::{generate_random_bytes, RngWrapper};

#[cfg(feature = "x509")]
use crate::asn1::ObjectIdentifier;
#[cfg(feature = "x509")]
use crate::crypto::aead::Aes256Gcm;
#[cfg(feature = "x509")]
use crate::crypto::kdf::HkdfSha3_256;
#[cfg(feature = "x509")]
use crate::der::oid::AssociatedOid;
use crate::Errorizable;

/// An ECIES public key that takes part in key exchange.
pub trait EciesPublicKeyOps: Clone + PartialEq + Eq {
	/// The secret key type that pairs with this public key.
	type SecretKey: EciesSecretKeyOps<PublicKey = Self>;

	/// The size in bytes of the encoded public key.
	const PUBLIC_KEY_SIZE: usize;

	/// Decode a public key from its byte encoding.
	fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self>
	where
		Self: Sized;

	/// Encode the public key as bytes.
	fn to_bytes(&self) -> Vec<u8>;
}

/// An ECIES secret key that generates keys and takes part in key exchange.
pub trait EciesSecretKeyOps: Clone {
	/// The public key type that pairs with this secret key.
	type PublicKey: EciesPublicKeyOps;

	/// The size in bytes of the encoded secret key.
	const SECRET_KEY_SIZE: usize;

	/// Generate a random secret key from `rng`.
	fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self;

	/// The public key that corresponds to this secret key.
	fn public_key(&self) -> Self::PublicKey;

	/// Run ECDH key agreement with `public_key` and return the raw shared
	/// secret.
	fn diffie_hellman(&self, public_key: &Self::PublicKey) -> EcdhSecret;
}

/// Ephemeral key generation for ECIES encryption.
pub trait EciesEphemeral {
	/// The public key type of the recipient and of the ephemeral key.
	type PublicKey: EciesPublicKeyOps;

	/// Generate a new ephemeral keypair and return its public key bytes with
	/// the ECDH shared secret.
	fn generate_ephemeral(
		recipient_pubkey: &Self::PublicKey,
		rng: &mut dyn rand_core::CryptoRngCore,
	) -> Result<(Vec<u8>, EcdhSecret)>;
}

/// An error from an ECIES operation.
#[derive(Errorizable, Debug, Clone)]
pub enum EciesError {
	/// The ciphertext has an invalid format or length.
	#[error("Invalid ECIES ciphertext format")]
	InvalidCiphertext,

	/// The public key bytes fail to decode.
	#[error("Invalid ECIES public key: {0}")]
	InvalidPublicKey(crate::crypto::k256::elliptic_curve::Error),

	/// The secret key bytes fail to decode.
	#[error("Invalid ECIES secret key: {0}")]
	InvalidSecretKey(crate::crypto::k256::elliptic_curve::Error),

	/// The AEAD failed to encrypt.
	#[error("ECIES encryption failed: {0}")]
	EncryptionFailed(crate::crypto::aead::Error),

	/// The AEAD failed to decrypt or to verify the tag.
	#[error("ECIES decryption failed: {0}")]
	DecryptionFailed(crate::crypto::aead::Error),

	/// The KDF failed to derive the content-encryption key.
	#[error("ECIES key derivation failed: {0}")]
	Kdf(KdfError),

	/// The random source failed to produce a nonce.
	///
	/// The draw fails as a [`TightBeamError`](crate::TightBeamError), which
	/// itself carries this enum, so the variant names the failure without
	/// carrying its source.
	#[error("ECIES randomness failed")]
	RandomGenerationFailed,
}

crate::impl_from!(KdfError => EciesError::Kdf);

/// The result of an ECIES operation.
pub type Result<T> = core::result::Result<T, EciesError>;

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

	fn diffie_hellman(&self, public_key: &Self::PublicKey) -> EcdhSecret {
		let shared_secret = diffie_hellman(self.to_nonzero_scalar(), public_key.as_affine());
		let bytes: [u8; ECDH_SHARED_SECRET_SIZE] = (*shared_secret.raw_secret_bytes()).into();
		Secret::from(bytes)
	}
}

impl core::convert::TryFrom<SecretSlice<u8>> for SecretKey {
	type Error = EciesError;
	fn try_from(bytes: SecretSlice<u8>) -> Result<Self> {
		bytes
			.with(|raw| SecretKey::from_slice(raw))
			.map_err(EciesError::InvalidSecretKey)
	}
}

impl From<&SecretKey> for SecretSlice<u8> {
	fn from(sk: &SecretKey) -> Self {
		let bytes = SecretKey::to_bytes(sk).to_vec();
		Secret::from(bytes)
	}
}

impl EciesEphemeral for SecretKey {
	type PublicKey = PublicKey;

	fn generate_ephemeral(
		recipient_pubkey: &Self::PublicKey,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(Vec<u8>, EcdhSecret)> {
		let mut wrapper = RngWrapper(rng);
		let ephemeral_secret = EphemeralSecret::random(&mut wrapper);
		let ephemeral_pubkey = ephemeral_secret.public_key();

		// Perform ECDH to get shared secret
		let shared_secret = ephemeral_secret.diffie_hellman(recipient_pubkey);

		let ephemeral_point = ephemeral_pubkey.to_encoded_point(true);
		let ephemeral_bytes = ephemeral_point.as_bytes().to_vec();
		let shared_bytes: [u8; ECDH_SHARED_SECRET_SIZE] = (*shared_secret.raw_secret_bytes()).into();
		Ok((ephemeral_bytes, Secret::from(shared_bytes)))
	}
}

/// An ECIES encrypted message whose sizes depend on the curve.
pub trait EciesMessageOps: Sized {
	/// The size in bytes of the ephemeral public key on this curve.
	const PUBKEY_SIZE: usize;

	/// Parse a message from its encoding,
	/// `ephemeral_pubkey || ciphertext_with_tag`.
	fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self>;

	/// Encode the message as `ephemeral_pubkey || ciphertext_with_tag`.
	fn to_bytes(&self) -> Vec<u8>;

	/// The ephemeral public key bytes.
	fn ephemeral_pubkey(&self) -> &[u8];

	/// The ciphertext bytes, laid out as `nonce || encrypted_data || tag`.
	fn ciphertext(&self) -> &[u8];
}

/// An ECIES encrypted message on the secp256k1 curve.
///
/// The encoded message holds these parts in order:
/// - `ephemeral_pubkey`: 33 bytes (compressed secp256k1 public key)
/// - `nonce`: 12 bytes (AES-GCM nonce)
/// - `ciphertext`: variable length (encrypted plaintext)
/// - `tag`: 16 bytes (AES-GCM authentication tag, appended to ciphertext)
pub struct Secp256k1EciesMessage {
	/// The ephemeral public key in compressed SEC1 encoding.
	ephemeral_pubkey: Vec<u8>,
	/// The nonce, the encrypted data, and the authentication tag, in order.
	ciphertext: Vec<u8>,
}

impl Secp256k1EciesMessage {
	/// The minimum ciphertext size, which is the nonce plus the tag.
	const MIN_CIPHERTEXT_SIZE: usize = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;

	/// Parse a message from its encoding,
	/// `ephemeral_pubkey || ciphertext_with_tag`.
	///
	/// # Errors
	///
	/// - [`EciesError::InvalidCiphertext`] when `bytes` is shorter than the
	///   public key plus the nonce and the tag.
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

	/// Encode the message as `ephemeral_pubkey || ciphertext_with_tag`.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(self.ephemeral_pubkey.len() + self.ciphertext.len());
		bytes.extend_from_slice(&self.ephemeral_pubkey);
		bytes.extend_from_slice(&self.ciphertext);
		bytes
	}

	/// Mutable access to the ephemeral public key bytes, for tampering tests.
	#[cfg(test)]
	pub(crate) fn ephemeral_pubkey_mut(&mut self) -> &mut Vec<u8> {
		&mut self.ephemeral_pubkey
	}

	/// Mutable access to the ciphertext bytes, for tampering tests.
	#[cfg(test)]
	pub(crate) fn ciphertext_mut(&mut self) -> &mut Vec<u8> {
		&mut self.ciphertext
	}
}

impl EciesMessageOps for Secp256k1EciesMessage {
	const PUBKEY_SIZE: usize = EC_PUBKEY_COMPRESSED_SIZE;

	fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
		let bytes = bytes.as_ref();
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

/// Encrypt `plaintext` to `recipient_pubkey` with ECIES.
///
/// The result holds the ephemeral public key and the ciphertext.
///
/// - `recipient_pubkey`: the recipient public key.
/// - `plaintext`: the data to encrypt.
/// - `associated_data`: optional authenticated associated data (AAD).
/// - `rng`: an optional cryptographically secure RNG. `None` uses `OsRng`.
///
/// # Type Parameters
///
/// - `PK`: the public key type, which implements [`EciesPublicKeyOps`].
/// - `P`: the plaintext type, which converts to bytes.
/// - `R`: the RNG type. `OsRng` serves when `rng` is `None`.
/// - `M`: the message type, which implements [`EciesMessageOps`].
/// - `K`: the KDF that derives the content-encryption key.
/// - `A`: the AEAD cipher that seals the plaintext.
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

	// The provided RNG and `OsRng` share this one body.
	macro_rules! do_encrypt {
		($rng:expr) => {{
			let (ephemeral_bytes, shared_secret) = PK::SecretKey::generate_ephemeral(recipient_pubkey, $rng)?;
			let cipher = shared_secret.content_cipher::<K, A>(&ephemeral_bytes)?;

			// The nonce is sized for the negotiated cipher. A failing random
			// source returns `RandomGenerationFailed` and never panics.
			let mut nonce = Nonce::<A>::default();
			let source: &mut dyn CryptoRngCore = &mut *$rng;
			generate_random_bytes(nonce.as_mut_slice(), Some(source))
				.map_err(|_| EciesError::RandomGenerationFailed)?;

			let payload = match associated_data {
				Some(aad) => Payload { msg: plaintext, aad },
				None => Payload { msg: plaintext, aad: b"" },
			};

			// One sized allocation holds the nonce and the ciphertext.
			let ciphertext = cipher.encrypt(&nonce, payload).map_err(EciesError::EncryptionFailed)?;
			let encrypted_len = ciphertext.len();
			let mut final_ciphertext = Vec::with_capacity(nonce.len() + encrypted_len);
			final_ciphertext.extend_from_slice(nonce.as_slice());
			final_ciphertext.extend_from_slice(&ciphertext);

			// One sized allocation holds the ephemeral key and the ciphertext.
			let total_len = ephemeral_bytes.len() + final_ciphertext.len();
			let mut wire_bytes = Vec::with_capacity(total_len);
			wire_bytes.extend_from_slice(&ephemeral_bytes);
			wire_bytes.extend_from_slice(&final_ciphertext);

			M::from_bytes(&wire_bytes)
		}};
	}

	match rng {
		Some(r) => do_encrypt!(r),
		None => do_encrypt!(&mut OsRng),
	}
}

/// Decrypt an ECIES `message` with the recipient secret key.
///
/// The shared secret S = d·R keys the content cipher, and
/// [`decrypt_with_shared_secret`] opens the message.
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
	let ephemeral_pubkey = <SK::PublicKey as EciesPublicKeyOps>::from_bytes(message.ephemeral_pubkey())?;
	let shared_secret = recipient_seckey.diffie_hellman(&ephemeral_pubkey);
	decrypt_with_shared_secret::<M, K, A>(message, shared_secret, associated_data)
}

/// Decrypt an ECIES message from a precomputed ECDH shared secret.
///
/// This function splits the `d·R` step out of [`decrypt`], so the recipient
/// private key can live behind an external boundary such as an HSM, a KMS, or
/// a secure enclave. The caller obtains the shared secret out of band, for
/// example from `SigningKeyProvider::key_agreement`, and passes it here for
/// key derivation and AEAD opening.
pub fn decrypt_with_shared_secret<M, K, A>(
	message: &M,
	shared_secret: EcdhSecret,
	associated_data: Option<&[u8]>,
) -> Result<SecretSlice<u8>>
where
	M: EciesMessageOps,
	K: KdfFunction,
	A: Aead + KeyInit,
{
	// The negotiated cipher sets the AEAD geometry.
	let nonce_size = <A as AeadCore>::NonceSize::USIZE;
	let tag_size = <A as AeadCore>::TagSize::USIZE;

	let ciphertext_bytes = message.ciphertext();
	if ciphertext_bytes.len() < nonce_size + tag_size {
		return Err(EciesError::InvalidCiphertext);
	}

	let nonce = Nonce::<A>::from_slice(&ciphertext_bytes[..nonce_size]);
	let ciphertext_with_tag = &ciphertext_bytes[nonce_size..];

	let cipher = shared_secret.content_cipher::<K, A>(message.ephemeral_pubkey())?;

	let payload = match associated_data {
		Some(aad) => Payload { msg: ciphertext_with_tag, aad },
		None => Payload { msg: ciphertext_with_tag, aad: b"" },
	};

	let plaintext = cipher.decrypt(nonce, payload).map_err(EciesError::DecryptionFailed)?;
	Ok(Secret::from(plaintext))
}

impl EcdhSecret {
	/// The AEAD cipher `A` keyed by KDF `K` from this shared secret.
	///
	/// The key is derived at the cipher's own key size and binds the ephemeral
	/// public key C0 for non-malleability. Encryption and decryption both key
	/// their cipher here, so the two sides cannot derive different keys.
	fn content_cipher<K, A>(self, ephemeral_pubkey: &[u8]) -> Result<A>
	where
		K: KdfFunction,
		A: KeyInit,
	{
		let key_size = <A as KeySizeUser>::KeySize::USIZE;
		let k_enc = self.ecies_kdf::<K>(ephemeral_pubkey, TIGHTBEAM_ECIES_KDF_INFO, None, key_size)?;
		let refused = EciesError::Kdf(KdfError::DerivationFailed(InvalidLength));

		let cipher = A::new_from_slice(&k_enc).map_err(|_| refused)?;
		Ok(cipher)
	}
}

/// Borrow the ephemeral public key from raw encoded ECIES bytes without a
/// copy.
pub fn ephemeral_pubkey_bytes<M>(bytes: &(impl AsRef<[u8]> + ?Sized)) -> Result<&[u8]>
where
	M: EciesMessageOps,
{
	let bytes = bytes.as_ref();
	bytes.get(..M::PUBKEY_SIZE).ok_or(EciesError::InvalidCiphertext)
}

#[cfg(feature = "x509")]
crate::define_oid_wrapper!(
	/// The OID of ECIES over secp256k1.
	EciesSecp256k1Oid,
	"1.3.132.1.12.0"
);

/// Encrypts messages to a recipient's secp256k1 public key with ECIES.
///
/// It implements [`Encryptor`](crate::crypto::aead::Encryptor), so
/// [`FrameBuilder::with_encryptor`] accepts it for asymmetric message
/// encryption.
///
/// # Example
///
/// ```
/// use tightbeam::crypto::aead::{DecryptContent, Encryptor};
/// use tightbeam::crypto::ecies::{EciesDecryptor, EciesEncryptor};
/// use tightbeam::crypto::k256::SecretKey;
/// use tightbeam::crypto::secret::ToInsecure;
/// use tightbeam::random::OsRng;
///
/// let recipient = SecretKey::random(&mut OsRng);
/// let encryptor = EciesEncryptor::new(recipient.public_key());
/// let info = encryptor.encrypt_content(b"hello", [], None)?;
///
/// let decryptor = EciesDecryptor::new(recipient);
/// let plaintext = decryptor.decrypt_content(&info)?.to_insecure();
/// assert_eq!(&plaintext[..], b"hello");
/// # Ok::<(), tightbeam::TightBeamError>(())
/// ```
///
/// [`FrameBuilder::with_encryptor`]: crate::builder::FrameBuilder::with_encryptor
#[cfg(feature = "x509")]
pub struct EciesEncryptor {
	recipient_pubkey: PublicKey,
}

#[cfg(feature = "x509")]
impl EciesEncryptor {
	/// Create an ECIES encryptor for `recipient_pubkey`.
	pub fn new(recipient_pubkey: PublicKey) -> Self {
		Self { recipient_pubkey }
	}

	/// Create an encryptor from SEC1-encoded public key bytes.
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
		let ecies_msg = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
			&self.recipient_pubkey,
			data.as_ref(),
			None,
			None::<&mut OsRng>,
		)?;

		// The encrypted content holds the full ECIES message, which is the
		// ephemeral public key followed by the ciphertext.
		let encrypted_bytes = ecies_msg.to_bytes();
		let content_type = content_type.unwrap_or(crate::oids::DATA);

		// The algorithm carries no nonce parameter, because the ECIES message
		// embeds the ephemeral public key.
		let content_enc_alg = crate::AlgorithmIdentifier { oid: EciesSecp256k1Oid::OID, parameters: None };
		let encrypted_content = Some(crate::der::asn1::OctetString::new(encrypted_bytes)?);

		Ok(crate::EncryptedContentInfo { content_type, content_enc_alg, encrypted_content })
	}
}

/// Decrypts ECIES messages with the recipient's secp256k1 secret key.
///
/// It implements [`Decryptor`](crate::crypto::aead::Decryptor), so a frame
/// decrypts with it through [`Frame::decrypt`](crate::Frame::decrypt).
///
/// See [`EciesEncryptor`] for a round trip.
#[cfg(feature = "x509")]
pub struct EciesDecryptor {
	secret_key: SecretKey,
}

#[cfg(feature = "x509")]
impl EciesDecryptor {
	/// Create an ECIES decryptor that holds `secret_key`.
	pub fn new(secret_key: SecretKey) -> Self {
		Self { secret_key }
	}
}

#[cfg(feature = "x509")]
impl crate::crypto::aead::Decryptor for EciesDecryptor {
	fn algorithm_oid(&self) -> ObjectIdentifier {
		EciesSecp256k1Oid::OID
	}

	fn open(&self, content: crate::crypto::aead::CheckedContent<'_>) -> crate::error::Result<SecretSlice<u8>> {
		let encrypted_bytes = content
			.info()
			.encrypted_content
			.as_ref()
			.ok_or(crate::TightBeamError::MissingEncryptionInfo)?
			.as_bytes();

		let ecies_msg = Secp256k1EciesMessage::from_bytes(encrypted_bytes)?;
		Ok(decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(&self.secret_key, &ecies_msg, None)?)
	}
}

/// ECIES decryptor driven by a precomputed ECDH shared secret.
///
/// Pairs with [`ephemeral_pubkey_bytes`] and an async key-agreement backend
/// (`SigningKeyProvider::key_agreement`) so the recipient private key can stay
/// inside an HSM, a KMS, or a secure enclave. It opens the secp256k1,
/// HKDF-SHA3-256, and AES-256-GCM suite that [`EciesSecp256k1Oid`] names.
#[cfg(feature = "x509")]
pub struct EciesSharedSecretDecryptor {
	shared_secret: EcdhSecret,
}

#[cfg(feature = "x509")]
impl EciesSharedSecretDecryptor {
	/// Build a decryptor from a precomputed ECDH shared secret.
	pub fn new(shared_secret: EcdhSecret) -> Self {
		Self { shared_secret }
	}
}

#[cfg(feature = "x509")]
impl crate::crypto::aead::Decryptor for EciesSharedSecretDecryptor {
	fn algorithm_oid(&self) -> ObjectIdentifier {
		EciesSecp256k1Oid::OID
	}

	fn open(&self, content: crate::crypto::aead::CheckedContent<'_>) -> crate::error::Result<SecretSlice<u8>> {
		let encrypted_bytes = content
			.info()
			.encrypted_content
			.as_ref()
			.ok_or(crate::TightBeamError::MissingEncryptionInfo)?
			.as_bytes();

		let ecies_msg = Secp256k1EciesMessage::from_bytes(encrypted_bytes)?;
		let shared_secret = self.shared_secret.with(|bytes| Secret::from(*bytes));
		Ok(decrypt_with_shared_secret::<Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
			&ecies_msg,
			shared_secret,
			None,
		)?)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::aead::Key;
	use crate::crypto::common::typenum::U48;
	use crate::crypto::secret::ToInsecure;
	use aead::{AeadInPlace, Tag};
	use rand_core::OsRng;

	fn keypair() -> (SecretKey, PublicKey) {
		let mut rng = OsRng;
		let secret = SecretKey::random(&mut rng);
		let public = secret.public_key();
		(secret, public)
	}

	/// AES-256-GCM behind a 48-byte key, wider than one 32-byte KDF block.
	struct WideKeyCipher(Aes256Gcm);

	impl KeySizeUser for WideKeyCipher {
		type KeySize = U48;
	}

	impl KeyInit for WideKeyCipher {
		fn new(key: &Key<Self>) -> Self {
			let (inner_key, _) = key.split_at(32);
			Self(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(inner_key)))
		}
	}

	impl AeadCore for WideKeyCipher {
		type NonceSize = <Aes256Gcm as AeadCore>::NonceSize;
		type TagSize = <Aes256Gcm as AeadCore>::TagSize;
		type CiphertextOverhead = <Aes256Gcm as AeadCore>::CiphertextOverhead;
	}

	impl AeadInPlace for WideKeyCipher {
		fn encrypt_in_place_detached(
			&self,
			nonce: &Nonce<Self>,
			associated_data: &[u8],
			buffer: &mut [u8],
		) -> aead::Result<Tag<Self>> {
			self.0.encrypt_in_place_detached(nonce, associated_data, buffer)
		}

		fn decrypt_in_place_detached(
			&self,
			nonce: &Nonce<Self>,
			associated_data: &[u8],
			buffer: &mut [u8],
			tag: &Tag<Self>,
		) -> aead::Result<()> {
			self.0.decrypt_in_place_detached(nonce, associated_data, buffer, tag)
		}
	}

	fn roundtrip(plaintext: impl AsRef<[u8]>, aad: Option<&[u8]>) -> Result<()> {
		let plaintext = plaintext.as_ref();
		let (secret, public) = keypair();
		let encrypted = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
			&public,
			plaintext,
			aad,
			None::<&mut OsRng>,
		)?;

		let decrypted = decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(&secret, &encrypted, aad)?;
		assert_eq!(plaintext, &decrypted.to_insecure()[..]);
		Ok(())
	}

	/// A cipher whose key is wider than one KDF block keys and round-trips,
	/// because the key is derived at the cipher's own size.
	#[test]
	fn a_key_wider_than_32_bytes_round_trips() -> Result<()> {
		let (secret, public) = keypair();
		let encrypted = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, WideKeyCipher>(
			&public,
			b"wide",
			None,
			None::<&mut OsRng>,
		)?;

		let decrypted = decrypt::<_, _, HkdfSha3_256, WideKeyCipher>(&secret, &encrypted, None)?;
		assert_eq!(&decrypted.to_insecure()[..], b"wide");
		Ok(())
	}

	#[test]
	fn test_ecies_encryption() -> Result<()> {
		// Each case is a `(plaintext, aad)` pair.
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

		// An explicit RNG exercises the `rng` parameter.
		let encrypted = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
			&public,
			plaintext,
			Some(correct_aad),
			Some(&mut rng),
		)?;
		// Each case is an `(aad, should_succeed)` pair.
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
				assert_eq!(&plaintext[..], &result?.to_insecure()[..]);
			}
		}

		Ok(())
	}

	#[test]
	fn test_serialization() -> Result<()> {
		let (secret, public) = keypair();
		let plaintext = b"Test serialization";

		// A message survives an encode and parse round trip.
		let encrypted = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
			&public,
			plaintext,
			None,
			None::<&mut OsRng>,
		)?;
		let bytes = encrypted.to_bytes();
		let parsed = Secp256k1EciesMessage::from_bytes(&bytes)?;
		let decrypted = decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(&secret, &parsed, None)?;
		assert_eq!(&plaintext[..], &decrypted.to_insecure()[..]);

		// Both keys survive an encode and decode round trip through the traits.
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
		let (_, public1) = keypair();
		let (secret2, _) = keypair();

		let encrypted = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>(
			&public1,
			plaintext,
			None,
			None::<&mut OsRng>,
		)?;
		// A wrong recipient derives a different ECDH shared secret, so AEAD tag
		// verification must fail.
		assert!(decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(&secret2, &encrypted, None).is_err());

		// A tampered message must fail authentication.
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
		// Each of these encodings is too short to parse.
		let invalid_ciphertexts = [
			vec![],
			vec![0u8; 32],
			vec![0u8; 33], // Missing ciphertext
			vec![0u8; 45], // 33 + 12 (less than min 33+16)
		];

		for data in invalid_ciphertexts {
			assert!(Secp256k1EciesMessage::from_bytes(&data).is_err());
		}

		// Malformed key bytes fail to decode.
		assert!(PublicKey::from_bytes([0xFFu8; 33]).is_err());
		assert!(SecretKey::try_from(Secret::from(vec![0x00u8; 32])).is_err());
		Ok(())
	}

	/// Decrypt an ECIES payload with the recipient private key held behind a
	/// `SigningKeyProvider`: the `d·R` step runs via `key_agreement`, then the
	/// shared-secret decryptor opens it through the standard `Decryptor`.
	#[cfg(all(feature = "x509", feature = "signature", feature = "ecdh", feature = "tokio"))]
	#[tokio::test]
	async fn shared_secret_decryptor_via_provider() -> crate::error::Result<()> {
		use crate::crypto::aead::{DecryptContent, Encryptor};
		use crate::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
		use crate::crypto::sign::ecdsa::Secp256k1SigningKey;

		let plaintext = b"hsm-backed ecies decryption";
		let (secret, public) = keypair();

		// Sender encrypts to the recipient public key.
		let info = EciesEncryptor::new(public).encrypt_content(plaintext, [], None)?;
		let wire = info.encrypted_content.as_ref().ok_or(EciesError::InvalidCiphertext)?.as_bytes();

		// The recipient borrows the ephemeral public key and runs d·R behind
		// the provider.
		let epk = ephemeral_pubkey_bytes::<Secp256k1EciesMessage>(wire)?;
		let provider = Secp256k1KeyProvider::from(Secp256k1SigningKey::from(secret));
		let shared = provider.key_agreement(epk).await?;

		// The standard `Decryptor` opens the message, as `Frame::decrypt_bytes`
		// does.
		let decryptor = EciesSharedSecretDecryptor::new(EcdhSecret::try_from(shared)?);
		let opened = decryptor.decrypt_content(&info)?.to_insecure();
		assert_eq!(
			&opened[..],
			plaintext,
			"provider key agreement must reproduce the ECIES plaintext"
		);
		Ok(())
	}
}
