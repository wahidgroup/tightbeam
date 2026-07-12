// Re-exports
pub use aead::*;
#[cfg(feature = "aes-gcm")]
pub use aes_gcm::{Aes128Gcm, Aes256Gcm, Key as Aes256GcmKey, Nonce as Aes256GcmNonce};
#[cfg(feature = "transport")]
pub use aes_kw;

use crate::asn1::ObjectIdentifier;
use crate::crypto::common::typenum::Unsigned;
use crate::crypto::secret::SecretSlice;
use crate::der::oid::AssociatedOid;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

// OID wrapper types for AEAD ciphers
#[cfg(feature = "aes-gcm")]
mod oid_wrappers {
	crate::define_oid_wrapper!(
		/// AES-128-GCM cipher OID wrapper
		Aes128GcmOid,
		"2.16.840.1.101.3.4.1.6"
	);

	crate::define_oid_wrapper!(
		/// AES-256-GCM cipher OID wrapper
		/// Note: The `aes-gcm` crate does not implement `AssociatedOid` directly.
		Aes256GcmOid,
		"2.16.840.1.101.3.4.1.46"
	);
}

#[cfg(feature = "aes-gcm")]
pub use oid_wrappers::*;

/// Object-safe AEAD trait for runtime polymorphism.
///
/// This trait provides a minimal object-safe interface for AEAD operations,
/// allowing different cipher types to be stored in a single type (`RuntimeAead`).
trait AeadOps: Send + Sync {
	/// Encrypt plaintext with the given nonce.
	fn encrypt_bytes(&self, nonce: &[u8], plaintext: &[u8]) -> core::result::Result<Vec<u8>, aead::Error>;

	/// Decrypt ciphertext with the given nonce.
	fn decrypt_bytes(&self, nonce: &[u8], ciphertext: &[u8]) -> core::result::Result<Vec<u8>, aead::Error>;

	/// Get the nonce size for this cipher.
	fn nonce_size(&self) -> usize;
}

/// Blanket implementation for all RustCrypto `Aead` types.
impl<A> AeadOps for A
where
	A: Aead + Send + Sync,
{
	fn encrypt_bytes(&self, nonce: &[u8], plaintext: &[u8]) -> core::result::Result<Vec<u8>, aead::Error> {
		self.encrypt(nonce.into(), plaintext)
	}

	fn decrypt_bytes(&self, nonce: &[u8], ciphertext: &[u8]) -> core::result::Result<Vec<u8>, aead::Error> {
		self.decrypt(nonce.into(), ciphertext)
	}

	fn nonce_size(&self) -> usize {
		<A as AeadCore>::NonceSize::USIZE
	}
}

/// Runtime-polymorphic AEAD cipher wrapper.
///
/// This allows the handshake orchestrator (which knows `P::AeadCipher` at compile time)
/// to construct the appropriate cipher, then pass it to the transport layer which stores
/// it as a type-erased `RuntimeAead`. The OID is stored alongside the cipher so encryption
/// produces correct `EncryptedContentInfo` structures.
///
/// The handshake negotiates the security profile and constructs the correct concrete
/// cipher type (e.g., `Aes256Gcm`, `Aes128Gcm`), then wraps it in `RuntimeAead` for
/// storage in the transport layer.
///
/// # Example
/// ```ignore
/// // In handshake orchestrator (knows P::AeadCipher at compile time)
/// let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
/// let runtime_aead = RuntimeAead::new(cipher, AES_256_GCM_OID);
///
/// // Transport stores RuntimeAead without knowing concrete type
/// transport.set_symmetric_key(runtime_aead);
/// ```
pub struct RuntimeAead {
	cipher: Box<dyn AeadOps>,
	oid: ObjectIdentifier,
}

impl RuntimeAead {
	/// Construct a new RuntimeAead from any RustCrypto AEAD cipher.
	///
	/// # Parameters
	/// - `cipher`: The concrete AEAD cipher (e.g., `Aes256Gcm`)
	/// - `oid`: The algorithm OID for this cipher
	pub fn new<A>(cipher: A, oid: ObjectIdentifier) -> Self
	where
		A: Aead + Send + Sync + 'static,
	{
		Self { cipher: Box::new(cipher), oid }
	}

	/// Get the algorithm OID for this cipher.
	pub fn algorithm_oid(&self) -> ObjectIdentifier {
		self.oid
	}

	/// Get the nonce size for this cipher.
	pub fn nonce_size(&self) -> usize {
		self.cipher.nonce_size()
	}
}

// ============================================================================
// Helper Functions for EncryptedContentInfo
// ============================================================================

/// Build an EncryptedContentInfo structure from components.
///
/// This helper encapsulates the common logic for constructing EncryptedContentInfo
/// from a ciphertext, nonce, content type, and algorithm OID.
#[inline]
fn build_encrypted_content_info(
	ciphertext: Vec<u8>,
	nonce: &[u8],
	content_type: Option<ObjectIdentifier>,
	algorithm_oid: ObjectIdentifier,
) -> crate::error::Result<crate::EncryptedContentInfo> {
	let content_type = content_type.unwrap_or(crate::oids::DATA);

	// Store the nonce in the algorithm parameters as an OctetString
	let nonce_octet_string = crate::der::asn1::OctetString::new(nonce)?;
	let parameters = Some(crate::der::Any::encode_from(&nonce_octet_string)?);

	let content_enc_alg = crate::AlgorithmIdentifier { oid: algorithm_oid, parameters };
	let encrypted_content = Some(crate::der::asn1::OctetString::new(ciphertext)?);

	Ok(crate::EncryptedContentInfo { content_type, content_enc_alg, encrypted_content })
}

/// Extract nonce and ciphertext from EncryptedContentInfo.
///
/// Both slices borrow directly from `info`. The nonce length is validated
/// against `expected_nonce_len`: NIST SP 800-38D §8.2 fixes the GCM nonce at
/// the cipher's nonce size (96 bits for AES-GCM here).
#[inline]
fn extract_nonce_and_ciphertext(
	info: &crate::EncryptedContentInfo,
	expected_nonce_len: usize,
) -> crate::error::Result<(&[u8], &[u8])> {
	// Extract ciphertext
	let ciphertext = info
		.encrypted_content
		.as_ref()
		.ok_or(crate::TightBeamError::MissingEncryptionInfo)?
		.as_bytes();

	// Extract nonce from algorithm parameters
	let nonce_any = info
		.content_enc_alg
		.parameters
		.as_ref()
		.ok_or(crate::TightBeamError::MissingEncryptionInfo)?;

	// Borrow the nonce bytes out of the Any without an owned OctetString copy
	let nonce_octet_string: crate::der::asn1::OctetStringRef<'_> = nonce_any.decode_as()?;
	let nonce = nonce_octet_string.as_bytes();
	if nonce.len() != expected_nonce_len {
		return Err(crate::TightBeamError::InvalidNonceLength(
			(nonce.len(), expected_nonce_len).into(),
		));
	}

	Ok((nonce, ciphertext))
}

// ============================================================================
// Encryptor/Decryptor Traits
// ============================================================================

/// Trait for encrypting data and producing EncryptedContentInfo
pub trait Encryptor<C>
where
	C: AssociatedOid,
{
	/// Encrypt data and return the encrypted content info
	fn encrypt_content(
		&self,
		data: impl AsRef<[u8]>,
		nonce: impl AsRef<[u8]>,
		content_type: Option<ObjectIdentifier>,
	) -> crate::error::Result<crate::EncryptedContentInfo>;
}

/// Trait for decrypting EncryptedContentInfo
pub trait Decryptor {
	/// Decrypt encrypted content info and return the plaintext bytes.
	/// The nonce is extracted from the algorithm parameters in the
	/// EncryptedContentInfo and validated against the cipher's nonce size.
	///
	/// Algorithm binding: [`RuntimeAead`] rejects a `content_enc_alg.oid`
	/// that differs from its negotiated OID. The blanket impl for bare
	/// `Aead` ciphers has no OID to compare against (the RustCrypto cipher
	/// types carry none), so callers of that impl pre-bind the cipher choice.
	///
	/// The plaintext is returned as a [`SecretSlice`] so it zeroizes on drop.
	fn decrypt_content(&self, info: &crate::EncryptedContentInfo) -> crate::error::Result<SecretSlice<u8>>;
}

// Implement Encryptor for any AEAD cipher
impl<C, A> Encryptor<C> for A
where
	C: AssociatedOid,
	A: Aead,
{
	fn encrypt_content(
		&self,
		data: impl AsRef<[u8]>,
		nonce: impl AsRef<[u8]>,
		content_type: Option<ObjectIdentifier>,
	) -> crate::error::Result<crate::EncryptedContentInfo> {
		let nonce_bytes = nonce.as_ref();
		let ciphertext = self.encrypt(nonce_bytes.into(), data.as_ref())?;
		build_encrypted_content_info(ciphertext, nonce_bytes, content_type, C::OID)
	}
}

// Implement Decryptor for any AEAD cipher
impl<A> Decryptor for A
where
	A: Aead,
{
	fn decrypt_content(&self, info: &crate::EncryptedContentInfo) -> crate::error::Result<SecretSlice<u8>> {
		let (nonce_bytes, ciphertext) = extract_nonce_and_ciphertext(info, <A as AeadCore>::NonceSize::USIZE)?;
		let plaintext = self.decrypt(nonce_bytes.into(), ciphertext)?;
		Ok(SecretSlice::from(plaintext))
	}
}

// Implement Encryptor for RuntimeAead (uses stored OID instead of generic C)
impl RuntimeAead {
	/// Encrypt data and return the encrypted content info.
	///
	/// This method is equivalent to `Encryptor::encrypt_content` but uses the
	/// runtime OID stored in this `RuntimeAead` instead of a compile-time generic.
	///
	/// # Nonce
	/// The caller supplies `nonce` and is responsible for its uniqueness. For
	/// GCM ciphers a `(key, nonce)` pair MUST never repeat.
	pub fn encrypt_content(
		&self,
		data: impl AsRef<[u8]>,
		nonce: impl AsRef<[u8]>,
		content_type: Option<ObjectIdentifier>,
	) -> crate::error::Result<crate::EncryptedContentInfo> {
		let nonce_bytes = nonce.as_ref();
		let ciphertext = self.cipher.encrypt_bytes(nonce_bytes, data.as_ref())?;
		build_encrypted_content_info(ciphertext, nonce_bytes, content_type, self.oid)
	}
}

// Implement Decryptor for RuntimeAead (see trait docs for algorithm binding)
impl Decryptor for RuntimeAead {
	fn decrypt_content(&self, info: &crate::EncryptedContentInfo) -> crate::error::Result<SecretSlice<u8>> {
		// Bind the wire-declared algorithm to the negotiated cipher: a
		// mismatched OID must never reach key material (CWE-345).
		if info.content_enc_alg.oid != self.oid {
			return Err(crate::TightBeamError::UnexpectedAlgorithm(
				(info.content_enc_alg.oid, self.oid).into(),
			));
		}

		let (nonce_bytes, ciphertext) = extract_nonce_and_ciphertext(info, self.cipher.nonce_size())?;
		let plaintext = self.cipher.decrypt_bytes(nonce_bytes, ciphertext)?;
		Ok(SecretSlice::from(plaintext))
	}
}

#[cfg(all(test, feature = "aes-gcm"))]
mod tests {
	use super::*;
	use crate::error::ReceivedExpectedError;
	use crate::TightBeamError;

	const NONCE: [u8; 12] = [0x24; 12];
	const PLAINTEXT: &[u8] = b"aead round trip";

	fn test_cipher() -> Aes256Gcm {
		Aes256Gcm::new(&[0x42u8; 32].into())
	}

	fn encrypted_info() -> crate::EncryptedContentInfo {
		Encryptor::<Aes256GcmOid>::encrypt_content(&test_cipher(), PLAINTEXT, NONCE, None).unwrap()
	}

	/// Re-encode the algorithm parameters with a nonce of the given length.
	fn with_nonce_len(mut info: crate::EncryptedContentInfo, len: usize) -> crate::EncryptedContentInfo {
		let nonce = crate::der::asn1::OctetString::new(vec![0x24; len]).unwrap();
		info.content_enc_alg.parameters = Some(crate::der::Any::encode_from(&nonce).unwrap());
		info
	}

	#[test]
	fn decrypt_content_round_trips() {
		let plaintext = test_cipher().decrypt_content(&encrypted_info()).unwrap();
		assert!(plaintext.with(|p| p == PLAINTEXT).unwrap());
	}

	#[test]
	fn decrypt_content_rejects_short_nonce() {
		let info = with_nonce_len(encrypted_info(), 8);
		let result = test_cipher().decrypt_content(&info);
		assert!(matches!(
			result,
			Err(TightBeamError::InvalidNonceLength(ReceivedExpectedError {
				received: 8,
				expected: 12
			}))
		));
	}

	#[test]
	fn decrypt_content_rejects_long_nonce() {
		let info = with_nonce_len(encrypted_info(), 16);
		let result = test_cipher().decrypt_content(&info);
		assert!(matches!(
			result,
			Err(TightBeamError::InvalidNonceLength(ReceivedExpectedError {
				received: 16,
				expected: 12
			}))
		));
	}

	#[test]
	fn runtime_aead_round_trips() {
		let runtime = RuntimeAead::new(test_cipher(), crate::oids::AES_256_GCM);
		let info = runtime.encrypt_content(PLAINTEXT, NONCE, None).unwrap();
		let plaintext = runtime.decrypt_content(&info).unwrap();
		assert!(plaintext.with(|p| p == PLAINTEXT).unwrap());
	}

	#[test]
	fn runtime_aead_rejects_algorithm_oid_mismatch() {
		let runtime = RuntimeAead::new(test_cipher(), crate::oids::AES_256_GCM);
		let mut info = runtime.encrypt_content(PLAINTEXT, NONCE, None).unwrap();
		info.content_enc_alg.oid = crate::oids::AES_128_GCM;

		let result = runtime.decrypt_content(&info);
		assert!(matches!(result, Err(TightBeamError::UnexpectedAlgorithm(_))));
	}

	#[test]
	fn runtime_aead_rejects_wire_nonce_length() {
		let runtime = RuntimeAead::new(test_cipher(), crate::oids::AES_256_GCM);
		let info = runtime.encrypt_content(PLAINTEXT, NONCE, None).unwrap();
		let info = with_nonce_len(info, 8);

		let result = runtime.decrypt_content(&info);
		assert!(matches!(result, Err(TightBeamError::InvalidNonceLength(_))));
	}
}
