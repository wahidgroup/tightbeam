#[cfg(not(feature = "std"))]
extern crate alloc;

// Re-exports
#[cfg(feature = "zeroize")]
pub use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::der::asn1::OctetString;
use crate::der::{Decode, Encode};
use crate::der::{DecodeValue, EncodeValue, Header, Length, Reader, Tag, Tagged, Writer};
use crate::error::Result;
use crate::matrix::MatrixError;
use crate::{Asn1Matrix, Frame};

#[cfg(feature = "signature")]
mod signature {
	pub use crate::cms::content_info::CmsVersion;
	pub use crate::cms::signed_data::{SignatureValue, SignerIdentifier};
	pub use crate::crypto::hash::Digest;
	pub use crate::crypto::key::SigningKeyProvider;
	pub use crate::der::oid::AssociatedOid;
	pub use crate::der::Any;
	pub use crate::spki::AlgorithmIdentifierOwned;
	pub use crate::x509::ext::pkix::SubjectKeyIdentifier;
	pub use crate::{SignerInfo, TightBeamError};
}

#[cfg(feature = "signature")]
use signature::*;

#[cfg(feature = "aead")]
mod encryption {
	pub use crate::crypto::key::EncryptingKeyProvider;
	pub use crate::EncryptedContentInfo;
}

#[cfg(feature = "aead")]
use encryption::*;

#[cfg(feature = "signature")]
pub type SignatureVerifier<E = TightBeamError> = Box<dyn FnOnce(&[u8], &SignerInfo) -> core::result::Result<(), E>>;
#[cfg(feature = "digest")]
pub type Digestor<E = TightBeamError> = Box<dyn FnOnce(&[u8]) -> core::result::Result<crate::DigestInfo, E>>;
#[cfg(feature = "kdf")]
pub type KeyDeriver<E = TightBeamError> = Box<dyn Fn(&[u8], &[u8], &[u8], usize) -> core::result::Result<Vec<u8>, E>>;
#[cfg(feature = "aead")]
pub type KeyWrapper<E = TightBeamError> = Box<dyn Fn(&[u8], &[u8]) -> core::result::Result<Vec<u8>, E>>;

impl AsRef<Frame> for Frame {
	fn as_ref(&self) -> &Frame {
		self
	}
}

impl Asn1Matrix {
	/// Validate invariants per spec.
	pub fn validate(&self) -> Result<()> {
		if self.n == 0 {
			return Err(MatrixError::InvalidN(self.n).into());
		}

		let n2 = (self.n as usize) * (self.n as usize);
		if self.data.len() != n2 {
			return Err(MatrixError::LengthMismatch { n: self.n, len: self.data.len() }.into());
		}

		Ok(())
	}
}

impl Default for Asn1Matrix {
	fn default() -> Self {
		Self { n: 1, data: Vec::new() }
	}
}

impl Tagged for Asn1Matrix {
	fn tag(&self) -> Tag {
		Tag::Sequence
	}
}

impl<'a> DecodeValue<'a> for Asn1Matrix {
	fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> crate::der::Result<Self> {
		reader.sequence(|seq: &mut der::NestedReader<'_, R>| {
			let n = u8::decode(seq)?;
			let data_os = OctetString::decode(seq)?;

			// Validate per spec
			if n == 0 {
				return Err(crate::der::ErrorKind::Value { tag: Tag::Integer }.into());
			}

			let data = data_os.as_bytes();
			let n2 = (n as usize) * (n as usize);
			if data.len() != n2 {
				return Err(crate::der::ErrorKind::Length { tag: Tag::OctetString }.into());
			}

			Ok(Self { n, data: data.to_vec() })
		})
	}
}

impl EncodeValue for Asn1Matrix {
	fn value_len(&self) -> crate::der::Result<Length> {
		// INTEGER(n) + OCTET STRING(data)
		let n_len = self.n.encoded_len()?;
		// Validate before encoding
		if self.n == 0 {
			return Err(crate::der::ErrorKind::Value { tag: Tag::Integer }.into());
		}

		let n2 = (self.n as usize) * (self.n as usize);
		if self.data.len() != n2 {
			return Err(crate::der::ErrorKind::Length { tag: Tag::OctetString }.into());
		}

		let os = crate::der::asn1::OctetString::new(self.data.as_slice())?;
		let os_len = os.encoded_len()?;
		let total = (n_len + os_len)?;
		Ok(total)
	}

	fn encode_value(&self, encoder: &mut impl Writer) -> crate::der::Result<()> {
		// Encode fields inside SEQUENCE
		self.n.encode(encoder)?;

		let os = crate::der::asn1::OctetString::new(self.data.as_slice())?;
		os.encode(encoder)
	}
}

impl<'a> Decode<'a> for Asn1Matrix {
	fn decode<R: Reader<'a>>(reader: &mut R) -> crate::der::Result<Self> {
		let header = reader.peek_header()?;
		Self::decode_value(reader, header)
	}
}

/// Create a SignatureInfo by signing data
#[macro_export]
#[cfg(feature = "signature")]
macro_rules! sign {
	($signer:expr, $data:expr) => {{
		let unsigned_bytes = $crate::encode(&$data)?;
		$signer(&unsigned_bytes)
	}};
}

/// Macro to sign a document and insert the signature
#[macro_export]
#[cfg(feature = "signature")]
macro_rules! notarize {
	// Pattern for Signatory trait objects (takes a reference)
	(tbs: $tbs:expr, position: $position:ident, signer: & $signer:expr) => {{
		use $crate::crypto::sign::Signatory;

		let unsigned_bytes = $crate::encode(&$tbs)?;
		let $position = Some($signer.to_signer_info(&unsigned_bytes)?);

		let mut tbs = $tbs;
		tbs.$position = $position;
		Ok::<_, $crate::TightBeamError>(tbs)
	}};

	// Pattern for callable (Box<dyn FnOnce> or closures)
	(tbs: $tbs:expr, position: $position:ident, signer: $signer:expr) => {{
		let unsigned_bytes = $crate::encode(&$tbs)?;
		let $position = Some($signer(&unsigned_bytes)?);

		let mut tbs = $tbs;
		tbs.$position = $position;
		Ok::<_, $crate::TightBeamError>(tbs)
	}};
}

#[cfg(feature = "compress")]
#[macro_export]
macro_rules! compress {
	($alg:ident, $data:expr) => {{
		$crate::utils::compress($data, $crate::AlgorithmIdentifierOwned::$alg)
	}};
}

#[cfg(feature = "compress")]
#[macro_export]
macro_rules! decompress {
	($alg:ident, $data:expr) => {{
		$crate::utils::decompress($data, $crate::AlgorithmIdentifierOwned::$alg)
	}};
}

#[cfg(feature = "std")]
#[macro_export]
macro_rules! rwlock {
	// Single declaration with default
	($name:ident: $ty:ty = $default:expr) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::RwLock<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::RwLock<$ty>> {
				[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::RwLock::new($default)))
					|> std::sync::Arc::clone
			}
		}
	};

	// Single declaration without default (uses Default trait)
	($name:ident: $ty:ty) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::RwLock<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::RwLock<$ty>> {
				[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::RwLock::new(Default::default())))
					.clone()
			}
		}
	};

	// Multiple declarations
	($($name:ident: $ty:ty $(= $default:expr)?),+ $(,)?) => {
		$(
			$crate::rwlock!($name: $ty $(= $default)?);
		)+
	};
}

#[cfg(feature = "std")]
#[macro_export]
macro_rules! mutex {
	// Single declaration with default
	($name:ident: $ty:ty = $default:expr) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::Mutex<$ty>> {
				[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new($default)))
					.clone()
			}
		}
	};

	// Single declaration without default (uses Default trait)
	($name:ident: $ty:ty) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::Mutex<$ty>> {
				[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new(Default::default())))
					.clone()
			}
		}
	};

	// Multiple declarations
	($($name:ident: $ty:ty $(= $default:expr)?),+ $(,)?) => {
		$(
			$crate::mutex!($name: $ty $(= $default)?);
		)+
	};
}

/// Extension trait for Frame to add compute_hash method
#[cfg(feature = "digest")]
pub trait FrameHashExt {
	/// Compute hash of the frame using the specified digest algorithm
	fn compute_hash<D>(&self) -> Result<crate::DigestInfo>
	where
		D: digest::Digest + crate::der::oid::AssociatedOid;
}

#[cfg(feature = "digest")]
impl FrameHashExt for crate::Frame {
	fn compute_hash<D>(&self) -> Result<crate::DigestInfo>
	where
		D: digest::Digest + crate::der::oid::AssociatedOid,
	{
		let encoded = crate::encode(self)?;
		crate::utils::digest::<D>(&encoded)
	}
}

#[cfg(feature = "signature")]
impl crate::Frame {
	/// Sign the frame with the provided key provider.
	///
	/// This method encodes the frame (without the signature field) and signs it
	/// using the provided key provider. The signature is stored in the
	/// `nonrepudiation` field. It is useful if you require an async
	/// `KeyProvider` and cannot sign the frame synchronously (HSM, KMS, etc.).
	///
	/// # Parameters
	/// - `provider`: A key provider implementing the `KeyProvider` trait
	/// - `digest`: The digest algorithm to use for computing the message digest
	///
	/// # Returns
	/// The signed frame with the `nonrepudiation` field populated.
	pub async fn sign_with_provider<D, P>(mut self, provider: &P) -> Result<Self>
	where
		D: Digest + AssociatedOid,
		P: SigningKeyProvider,
	{
		// 1. Encode the frame (without signature field)
		let unsigned_bytes = crate::encode(&self)?;

		// 2. Compute digest
		let mut hasher = D::new();
		hasher.update(&unsigned_bytes);

		let digest = hasher.finalize();
		let digest_bytes = digest.as_slice();

		// 3. Sign the digest using the key provider
		let signature_bytes = provider.sign(digest_bytes).await?;
		let signature_value = SignatureValue::new(signature_bytes.as_slice())?;

		// 4. Get signature algorithm from provider
		let signature_algorithm = provider.algorithm();

		// 5. Compute signer identifier from public key
		let public_key_der = provider.to_public_key_bytes().await?;
		let mut hasher = D::new();
		hasher.update(&public_key_der);

		let skid_digest = hasher.finalize();
		let skid_octets = OctetString::new(&skid_digest.as_slice()[..20])?;
		let skid = SubjectKeyIdentifier::from(skid_octets);
		let sid = SignerIdentifier::SubjectKeyIdentifier(skid);

		// 6. Build digest algorithm identifier
		let digest_alg = AlgorithmIdentifierOwned { oid: D::OID, parameters: None };

		// 7. Create SignerInfo
		let signer_info = SignerInfo {
			version: CmsVersion::V1,
			sid,
			digest_alg,
			signed_attrs: None,
			signature_algorithm,
			signature: signature_value,
			unsigned_attrs: None,
		};

		self.nonrepudiation = Some(signer_info);

		Ok(self)
	}
}

#[cfg(feature = "aead")]
impl crate::Frame {
	/// Encrypt the frame message with the provided encryption key provider.
	///
	/// This method encrypts the message bytes using the provided encryption key
	/// provider and stores the encrypted content info in the `confidentiality`
	/// field. The encrypted bytes are stored in the `message` field. It is useful
	/// if you require an async `EncryptingKeyProvider` and cannot encrypt the
	/// frame synchronously (HSM, KMS, etc.).
	///
	/// # Parameters
	/// - `provider`: An encryption key provider implementing the `EncryptingKeyProvider` trait
	/// - `nonce_size`: The size of the nonce in bytes (e.g., 12 for AES-GCM)
	///
	/// # Returns
	/// The encrypted frame with the `confidentiality` field populated and encrypted
	/// bytes in the `message` field.
	pub async fn encrypt_with_provider<P>(mut self, provider: &P, nonce_size: usize) -> Result<Self>
	where
		P: EncryptingKeyProvider,
	{
		// 1. Generate random nonce
		let mut nonce = vec![0u8; nonce_size];
		crate::random::generate_random_bytes(&mut nonce, None)?;

		// 2. Encrypt the message bytes
		let ciphertext = provider.encrypt(&nonce, &self.message).await?;

		// 3. Get encryption algorithm from provider
		let content_enc_alg = provider.algorithm();

		// 4. Store nonce in algorithm parameters
		let nonce_octets = OctetString::new(nonce.as_slice())?;
		let parameters = Some(Any::encode_from(&nonce_octets)?);
		let content_enc_alg = AlgorithmIdentifierOwned { oid: content_enc_alg.oid, parameters };

		// 5. Create EncryptedContentInfo
		let content_type = crate::oids::DATA;
		let encrypted_content = Some(OctetString::new(ciphertext.as_slice())?);
		let encrypted_content_info = EncryptedContentInfo { content_type, content_enc_alg, encrypted_content };

		// 6. Update frame
		self.metadata.confidentiality = Some(encrypted_content_info);
		self.message = ciphertext;

		Ok(self)
	}

	/// Decrypt the frame message with the provided encryption key provider.
	///
	/// This method extracts the nonce from the `confidentiality` field's
	/// algorithm parameters and decrypts the message bytes using the provided
	/// encryption key provider. The decrypted bytes are stored back in the
	/// `message` field, and the `confidentiality` field is cleared. It is
	/// useful if you require an async `EncryptingKeyProvider` and cannot
	/// decrypt the frame synchronously (HSM, KMS, etc.).
	///
	/// # Parameters
	/// - `provider`: An encryption key provider implementing the `EncryptingKeyProvider` trait
	///
	/// # Returns
	/// The decrypted frame with plaintext bytes in the `message` field and
	/// `confidentiality` field cleared.
	pub async fn decrypt_with_provider<P>(mut self, provider: &P) -> Result<Self>
	where
		P: EncryptingKeyProvider,
	{
		// 1. Extract EncryptedContentInfo
		let encrypted_content_info = self
			.metadata
			.confidentiality
			.take()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;

		// 2. Extract ciphertext from message field
		let ciphertext = self.message.as_slice();

		// 3. Extract nonce from algorithm parameters
		let nonce_any = encrypted_content_info
			.content_enc_alg
			.parameters
			.as_ref()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;

		let nonce_octet_string: OctetString = nonce_any.decode_as()?;
		let nonce = nonce_octet_string.as_bytes();

		// 4. Decrypt using the provider
		let plaintext = provider.decrypt(nonce, ciphertext).await?;

		// 5. Update frame
		self.message = plaintext;

		Ok(self)
	}
}

#[cfg(test)]
mod tests {
	#[cfg(not(feature = "std"))]
	use alloc::string::ToString;

	#[cfg(feature = "signature")]
	mod notarize {
		use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
		use crate::error::Result;

		#[test]
		fn test_notarize_macro() -> Result<()> {
			let mut tbs = crate::testing::create_v0_tightbeam(None, None);
			tbs.nonrepudiation = None; // Ensure no signature initially

			let secret_bytes = [1u8; 32];
			let signing_key = Secp256k1SigningKey::from_bytes(&secret_bytes.into())?;

			// Use & to match the first pattern (Signatory trait)
			let notarized = notarize!(tbs: tbs, position: nonrepudiation, signer: &signing_key)?;
			assert!(notarized.nonrepudiation.is_some());

			Ok(())
		}
	}

	#[cfg(all(feature = "signature", feature = "secp256k1", feature = "tokio"))]
	mod sign {
		use crate::builder::frame::FrameBuilder;
		use crate::builder::TypeBuilder;
		use crate::cms::content_info::CmsVersion;
		use crate::cms::signed_data::SignerIdentifier;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::key::Secp256k1KeyProvider;
		use crate::error::Result;
		use crate::testing::{create_test_message, create_test_signing_key};
		use crate::Version;

		#[tokio::test]
		async fn test_frame_sign_with_key_provider() -> Result<()> {
			let message = create_test_message(None);
			let frame = FrameBuilder::from(Version::V1)
				.with_id("test-sign")
				.with_order(1696521600)
				.with_message(message)
				.build()?;
			assert!(frame.nonrepudiation.is_none());

			let signing_key = create_test_signing_key();
			let provider = Secp256k1KeyProvider::from(signing_key);

			let signed_frame = frame.sign_with_provider::<Sha3_256, _>(&provider).await?;
			assert!(signed_frame.nonrepudiation.is_some());

			let signer_info = signed_frame.nonrepudiation.as_ref().unwrap();
			assert_eq!(signer_info.version, CmsVersion::V1);
			assert!(matches!(signer_info.sid, SignerIdentifier::SubjectKeyIdentifier(_)));

			Ok(())
		}
	}

	#[cfg(all(feature = "aead", feature = "aes-gcm", feature = "tokio"))]
	mod encrypt {
		use crate::builder::frame::FrameBuilder;
		use crate::builder::TypeBuilder;
		use crate::crypto::aead::{Aes256Gcm, KeyInit};
		use crate::crypto::key::Aes256GcmKeyProvider;
		use crate::error::Result;
		use crate::testing::create_test_message;
		use crate::Version;

		#[tokio::test]
		async fn test_frame_encrypt_decrypt_roundtrip() -> Result<()> {
			let message = create_test_message(None);
			let original_message_bytes = crate::encode(&message)?;

			// Create frame
			let frame = FrameBuilder::from(Version::V1)
				.with_id("test-encrypt")
				.with_order(1696521600)
				.with_message(message)
				.build()?;
			assert!(frame.metadata.confidentiality.is_none());
			assert_eq!(frame.message, original_message_bytes);

			// Create encryption key provider
			let key_bytes = [42u8; 32];
			let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
			let provider = Aes256GcmKeyProvider::from(cipher);

			// Encrypt
			let encrypted_frame = frame.encrypt_with_provider(&provider, 12).await?;
			assert!(encrypted_frame.metadata.confidentiality.is_some());
			assert_ne!(encrypted_frame.message, original_message_bytes);

			// Decrypt
			let decrypted_frame = encrypted_frame.decrypt_with_provider(&provider).await?;
			assert!(decrypted_frame.metadata.confidentiality.is_none());
			assert_eq!(decrypted_frame.message, original_message_bytes);

			Ok(())
		}
	}
}
