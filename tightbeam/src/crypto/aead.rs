// Re-exports
pub use aead::*;
#[cfg(feature = "aes-gcm")]
pub use aes_gcm::{Aes256Gcm, Key as Aes256GcmKey, Nonce as Aes256GcmNonce};

#[cfg(feature = "aes-gcm")]
use der::oid::{AssociatedOid, ObjectIdentifier};

/// Create a wrapper type for AES-256-GCM with the OID
/// Note: The `aes-gcm` crate does not implement `AssociatedOid` directly.
#[cfg(feature = "aes-gcm")]
pub struct Aes256GcmOid;

#[cfg(feature = "aes-gcm")]
impl AssociatedOid for Aes256GcmOid {
	const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46");
}

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
	/// Decrypt encrypted content info and return the plaintext bytes
	/// The nonce is extracted from the algorithm parameters in the EncryptedContentInfo
	fn decrypt_content(&self, info: &crate::EncryptedContentInfo) -> crate::error::Result<Vec<u8>>;
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
		let nonce_ref = aead::Nonce::<A>::from_slice(nonce.as_ref());
		let ciphertext = self.encrypt(nonce_ref, data.as_ref())?;
		let content_type = content_type.unwrap_or(crate::asn1::DATA_OID);

		// Store the nonce in the algorithm parameters as an OctetString
		let nonce_octet_string = crate::der::asn1::OctetString::new(nonce.as_ref())?;
		let parameters = Some(crate::der::Any::encode_from(&nonce_octet_string)?);

		let content_enc_alg = crate::AlgorithmIdentifier { oid: C::OID, parameters };
		let encrypted_content = Some(crate::der::asn1::OctetString::new(ciphertext)?);
		Ok(crate::EncryptedContentInfo { content_type, content_enc_alg, encrypted_content })
	}
}

// Implement Decryptor for any AEAD cipher
impl<A> Decryptor for A
where
	A: Aead,
{
	fn decrypt_content(&self, info: &crate::EncryptedContentInfo) -> crate::error::Result<Vec<u8>> {
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

		// Decode the nonce from the Any type - use decode_as to get the OctetString
		let nonce_octet_string: crate::der::asn1::OctetString = nonce_any.decode_as()?;
		let nonce_ref = aead::Nonce::<A>::from_slice(nonce_octet_string.as_bytes());

		// Decrypt
		let plaintext = self.decrypt(nonce_ref, ciphertext)?;
		Ok(plaintext)
	}
}
