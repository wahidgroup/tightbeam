#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(
	not(feature = "std"),
	any(feature = "signature", feature = "digest", feature = "kdf", feature = "aead")
))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), any(feature = "kdf", feature = "aead")))]
use alloc::vec::Vec;

#[cfg(feature = "zeroize")]
pub use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::der::asn1::OctetString;
use crate::der::{Decode, Encode};
use crate::der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};
use crate::error::Result;
use crate::matrix::MatrixError;
use crate::{Asn1Matrix, Frame};

#[cfg(any(feature = "signature", feature = "digest", feature = "kdf", feature = "aead"))]
use crate::TightBeamError;

#[cfg(feature = "signature")]
mod signature {
	pub use crate::cms::signed_data::SignerIdentifier;
	pub use crate::crypto::hash::Digest;
	pub use crate::crypto::key::SigningKeyProvider;
	pub use crate::crypto::sign::SignerInfoExt;
	pub use crate::der::oid::AssociatedOid;
	pub use crate::x509::ext::pkix::SubjectKeyIdentifier;
	pub use crate::SignerInfo;

	#[cfg(not(feature = "aead"))]
	pub use crate::spki::AlgorithmIdentifierOwned;
}

#[cfg(feature = "signature")]
use signature::*;

#[cfg(feature = "aead")]
mod encryption {
	pub use crate::crypto::key::EncryptingKeyProvider;
	pub use crate::der::Any;
	pub use crate::spki::AlgorithmIdentifierOwned;
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
	/// Smallest valid matrix (1×1, zeroed) so the `data.len() == n*n`
	/// invariant holds for every reachable value. The encoder rejects
	/// non-conforming lengths.
	fn default() -> Self {
		Self { n: 1, data: vec![0u8; 1] }
	}
}

impl FixedTag for Asn1Matrix {
	const TAG: Tag = Tag::Sequence;
}

impl<'a> DecodeValue<'a> for Asn1Matrix {
	fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> crate::der::Result<Self> {
		let n = u8::decode(reader)?;
		let data_os = OctetString::decode(reader)?;

		// Strict validation at the untrusted decode boundary, per spec.
		if n == 0 {
			return Err(crate::der::ErrorKind::Value { tag: Tag::Integer }.into());
		}

		let data = data_os.as_bytes();
		let n2 = (n as usize) * (n as usize);
		if data.len() != n2 {
			return Err(crate::der::ErrorKind::Length { tag: Tag::OctetString }.into());
		}

		Ok(Self { n, data: data.to_vec() })
	}
}

impl EncodeValue for Asn1Matrix {
	fn value_len(&self) -> crate::der::Result<Length> {
		// The value is INTEGER(n) followed by OCTET STRING(data).
		let n_len = self.n.encoded_len()?;
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
		self.n.encode(encoder)?;

		let os = crate::der::asn1::OctetString::new(self.data.as_slice())?;
		os.encode(encoder)
	}
}

/// Create a SignatureInfo by signing data.
#[macro_export]
#[cfg(feature = "signature")]
macro_rules! sign {
	($signer:expr, $data:expr) => {{
		let unsigned_bytes = $crate::encode(&$data)?;
		$signer(&unsigned_bytes)
	}};
}

/// Macro to sign a document and insert the signature.
#[macro_export]
#[cfg(feature = "signature")]
macro_rules! notarize {
	// Pattern for Signatory trait objects (takes a reference).
	(tbs: $tbs:expr, position: $position:ident, signer: & $signer:expr) => {{
		use $crate::crypto::sign::Signatory;

		let unsigned_bytes = $crate::encode(&$tbs)?;
		let $position = Some($signer.to_signer_info(&unsigned_bytes)?);

		let mut tbs = $tbs;
		tbs.$position = $position;
		Ok::<_, $crate::TightBeamError>(tbs)
	}};

	// Pattern for callables (Box<dyn FnOnce> or closures).
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
				std::sync::Arc::clone(
					[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::RwLock::new($default)))
				)
			}
		}
	};

	// Single declaration without default (uses Default trait)
	($name:ident: $ty:ty) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::RwLock<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::RwLock<$ty>> {
				std::sync::Arc::clone(
					[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::RwLock::new(Default::default())))
				)
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
				std::sync::Arc::clone(
					[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new($default)))
				)
			}
		}
	};

	// Single declaration without default (uses Default trait)
	($name:ident: $ty:ty) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::Mutex<$ty>> {
				std::sync::Arc::clone(
					[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new(Default::default())))
				)
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

/// Extension trait for `Frame` that adds the `compute_hash` method.
#[cfg(feature = "digest")]
pub trait FrameHashExt {
	/// Compute the hash of the frame using the specified digest algorithm.
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
	///
	/// # See also
	/// - [`Frame::verify`](crate::Frame::verify): the verification
	///   counterpart under the same canonical convention
	pub async fn sign_with_provider<D, P>(self, provider: &P) -> Result<Self>
	where
		D: Digest + AssociatedOid,
		P: SigningKeyProvider + ?Sized,
	{
		let unsigned_bytes = self.to_tbs()?;

		// The canonical convention hashes the TBS bytes once with `D`,
		// then the provider signs that prehash. The digest algorithm
		// recorded in the SignerInfo below is therefore the digest
		// actually used by the signature.
		let mut tbs_hasher = D::new();
		tbs_hasher.update(&unsigned_bytes);

		let signature_bytes = provider.sign_prehash(&tbs_hasher.finalize()).await?;
		let signature_algorithm = provider.algorithm();

		let public_key_der = provider.to_public_key_bytes().await?;
		let mut hasher = D::new();
		hasher.update(&public_key_der);

		// RFC 5280 s4.2.1.2 method (1): SKID is a 160-bit (20-byte) hash of the
		// public key. Digests shorter than the window are a caller error.
		let skid_digest = hasher.finalize();
		let skid_bytes = skid_digest.as_slice().get(..20).ok_or(TightBeamError::InvalidAlgorithm)?;
		let skid_octets = OctetString::new(skid_bytes)?;
		let skid = SubjectKeyIdentifier::from(skid_octets);
		let sid = SignerIdentifier::SubjectKeyIdentifier(skid);
		let digest_alg = AlgorithmIdentifierOwned { oid: D::OID, parameters: None };
		let signer_info = SignerInfo::from_parts(signature_bytes, signature_algorithm, digest_alg, sid)?;

		Ok(self.attach_signer_info(signer_info))
	}

	/// Attach a precomputed [`SignerInfo`] to the frame's `nonrepudiation` field.
	///
	/// Completes detached / two-phase signing: pair with `Frame::to_tbs` to sign
	/// the canonical to-be-signed bytes with any external backend, then reattach
	/// the result here.
	pub fn attach_signer_info(mut self, signer_info: SignerInfo) -> Self {
		self.nonrepudiation = Some(signer_info);
		self
	}

	/// Attach a precomputed signature from its raw parts.
	///
	/// Convenience over [`Frame::attach_signer_info`] that assembles the
	/// [`SignerInfo`] from the signature bytes and algorithm identifiers.
	pub fn attach_signature(
		self,
		signature: impl AsRef<[u8]>,
		signature_algorithm: AlgorithmIdentifierOwned,
		digest_alg: AlgorithmIdentifierOwned,
		sid: SignerIdentifier,
	) -> Result<Self> {
		let signer_info = SignerInfo::from_parts(signature, signature_algorithm, digest_alg, sid)?;
		Ok(self.attach_signer_info(signer_info))
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
		let mut nonce = vec![0u8; nonce_size];
		crate::random::generate_random_bytes(&mut nonce, None)?;

		let ciphertext = provider.encrypt(&nonce, &self.message).await?;
		let content_enc_alg = provider.algorithm();

		// The nonce travels in the algorithm parameters so the receiver
		// can decrypt without out-of-band state.
		let nonce_octets = OctetString::new(nonce.as_slice())?;
		let parameters = Some(Any::encode_from(&nonce_octets)?);
		let content_enc_alg = AlgorithmIdentifierOwned { oid: content_enc_alg.oid, parameters };

		let content_type = crate::oids::DATA;
		let encrypted_content = Some(OctetString::new(ciphertext.as_slice())?);
		let encrypted_content_info = EncryptedContentInfo { content_type, content_enc_alg, encrypted_content };

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
		let encrypted_content_info = self
			.metadata
			.confidentiality
			.take()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;

		let ciphertext = self.message.as_slice();

		let nonce_any = encrypted_content_info
			.content_enc_alg
			.parameters
			.as_ref()
			.ok_or(TightBeamError::MissingEncryptionInfo)?;

		let nonce_octet_string: OctetString = nonce_any.decode_as()?;
		let nonce = nonce_octet_string.as_bytes();

		let plaintext = provider.decrypt(nonce, ciphertext).await?;
		self.message = plaintext;

		Ok(self)
	}
}

#[cfg(test)]
mod tests {
	#[cfg(not(feature = "std"))]
	use alloc::string::ToString;

	#[cfg(feature = "std")]
	mod statics {
		#[derive(Debug, Default, PartialEq)]
		struct Counter(u64);

		rwlock!(SHARED_RWLOCK_DEFAULTED: Counter = Counter(7));
		rwlock!(SHARED_RWLOCK: Counter);
		mutex!(SHARED_MUTEX_DEFAULTED: Counter = Counter(7));
		mutex!(SHARED_MUTEX: Counter);
		rwlock! {
			MULTI_RWLOCK_A: Counter,
			MULTI_RWLOCK_B: Counter = Counter(3),
		}
		mutex! {
			MULTI_MUTEX_A: Counter,
			MULTI_MUTEX_B: Counter = Counter(3),
		}

		#[test]
		fn rwlock_arms_initialize_and_share_state() -> crate::error::Result<()> {
			assert_eq!(*SHARED_RWLOCK_DEFAULTED().read()?, Counter(7));
			assert_eq!(*SHARED_RWLOCK().read()?, Counter(0));
			assert_eq!(*MULTI_RWLOCK_A().read()?, Counter(0));
			assert_eq!(*MULTI_RWLOCK_B().read()?, Counter(3));

			SHARED_RWLOCK().write()?.0 = 42;
			assert_eq!(*SHARED_RWLOCK().read()?, Counter(42));

			Ok(())
		}

		#[test]
		fn mutex_arms_initialize_and_share_state() -> crate::error::Result<()> {
			assert_eq!(*SHARED_MUTEX_DEFAULTED().lock()?, Counter(7));
			assert_eq!(*SHARED_MUTEX().lock()?, Counter(0));
			assert_eq!(*MULTI_MUTEX_A().lock()?, Counter(0));
			assert_eq!(*MULTI_MUTEX_B().lock()?, Counter(3));

			SHARED_MUTEX().lock()?.0 = 42;
			assert_eq!(*SHARED_MUTEX().lock()?, Counter(42));

			Ok(())
		}
	}

	mod asn1_matrix {
		use crate::error::Result;
		use crate::Asn1Matrix;

		#[test]
		fn default_upholds_invariant() -> Result<()> {
			let matrix = Asn1Matrix::default();
			assert_eq!(matrix.n, 1);
			assert_eq!(matrix.data.as_slice(), &[0u8]);

			matrix.validate()?;

			Ok(())
		}

		#[test]
		fn default_round_trips_through_der() -> Result<()> {
			let matrix = Asn1Matrix::default();

			let encoded = crate::encode(&matrix)?;
			let decoded: Asn1Matrix = crate::decode(&encoded)?;
			assert_eq!(decoded, matrix);

			Ok(())
		}
	}

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
		use crate::testing::utils::SixteenByteDigest;
		use crate::testing::{create_test_message, create_test_signing_key};
		use crate::{TightBeamError, Version};

		#[tokio::test]
		async fn rejects_digest_shorter_than_skid_window() -> Result<()> {
			let message = create_test_message(None);
			let frame = FrameBuilder::from(Version::V1)
				.with_id("test-short-digest")
				.with_order(1696521600)
				.with_message(message)
				.build()?;

			let signing_key = create_test_signing_key();
			let provider = Secp256k1KeyProvider::from(signing_key);

			let result = frame.sign_with_provider::<SixteenByteDigest, _>(&provider).await;
			assert!(matches!(result, Err(TightBeamError::InvalidAlgorithm)));

			Ok(())
		}

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
			let Some(signer_info) = signed_frame.nonrepudiation.as_ref() else {
				return Err(crate::error::TightBeamError::MissingSignatureInfo);
			};
			assert_eq!(signer_info.version, CmsVersion::V1);
			assert!(matches!(signer_info.sid, SignerIdentifier::SubjectKeyIdentifier(_)));

			Ok(())
		}
	}

	#[cfg(all(feature = "signature", feature = "secp256k1"))]
	mod detached_sign {
		use crate::builder::frame::FrameBuilder;
		use crate::builder::TypeBuilder;
		use crate::cms::content_info::CmsVersion;
		use crate::cms::signed_data::SignerIdentifier;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::sign::ecdsa::Secp256k1Signature;
		use crate::crypto::sign::{
			secp256k1_signer_identifier, sign_canonical, SignatureAlgorithmIdentifier, SignerInfoExt,
		};
		use crate::der::oid::AssociatedOid;
		use crate::error::Result;
		use crate::spki::AlgorithmIdentifierOwned;
		use crate::testing::{create_test_message, create_test_signing_key};
		use crate::{SignerInfo, Version};

		fn unsigned_frame() -> Result<crate::Frame> {
			let message = create_test_message(None);
			FrameBuilder::from(Version::V1)
				.with_id("test-detached")
				.with_order(1696521600)
				.with_message(message)
				.build()
		}

		#[test]
		fn test_attach_signature_roundtrip() -> Result<()> {
			let frame = unsigned_frame()?;
			let signing_key = create_test_signing_key();

			// External backends must follow the canonical convention.
			// SHA3-256 runs over the TBS bytes, and ECDSA signs that
			// prehash.
			let tbs = frame.to_tbs()?;
			let signature: Secp256k1Signature = sign_canonical::<Sha3_256, _>(&signing_key, &tbs)?;

			let sig_alg = AlgorithmIdentifierOwned { oid: Secp256k1Signature::ALGORITHM_OID, parameters: None };
			let digest_alg = AlgorithmIdentifierOwned { oid: Sha3_256::OID, parameters: None };
			let sid = secp256k1_signer_identifier(signing_key.verifying_key())?;

			let signed = frame.attach_signature(signature.to_bytes(), sig_alg, digest_alg, sid)?;
			assert!(signed.nonrepudiation.is_some());

			signed.verify::<Secp256k1Signature, Sha3_256>(signing_key.verifying_key())?;

			Ok(())
		}

		#[test]
		fn test_attach_signer_info_from_parts() -> Result<()> {
			let frame = unsigned_frame()?;
			let signing_key = create_test_signing_key();

			let tbs = frame.to_tbs()?;
			let signature: Secp256k1Signature = sign_canonical::<Sha3_256, _>(&signing_key, &tbs)?;

			let sig_alg = AlgorithmIdentifierOwned { oid: Secp256k1Signature::ALGORITHM_OID, parameters: None };
			let digest_alg = AlgorithmIdentifierOwned { oid: Sha3_256::OID, parameters: None };
			let sid = secp256k1_signer_identifier(signing_key.verifying_key())?;

			let signer_info = SignerInfo::from_parts(signature.to_bytes(), sig_alg, digest_alg, sid)?;
			assert_eq!(signer_info.version, CmsVersion::V1);
			assert!(matches!(signer_info.sid, SignerIdentifier::SubjectKeyIdentifier(_)));

			let signed = frame.attach_signer_info(signer_info);
			signed.verify::<Secp256k1Signature, Sha3_256>(signing_key.verifying_key())?;

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

			let frame = FrameBuilder::from(Version::V1)
				.with_id("test-encrypt")
				.with_order(1696521600)
				.with_message(message)
				.build()?;
			assert!(frame.metadata.confidentiality.is_none());
			assert_eq!(frame.message, original_message_bytes);

			let key_bytes = [42u8; 32];
			let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
			let provider = Aes256GcmKeyProvider::from(cipher);

			let encrypted_frame = frame.encrypt_with_provider(&provider, 12).await?;
			assert!(encrypted_frame.metadata.confidentiality.is_some());
			assert_ne!(encrypted_frame.message, original_message_bytes);

			let decrypted_frame = encrypted_frame.decrypt_with_provider(&provider).await?;
			assert!(decrypted_frame.metadata.confidentiality.is_none());
			assert_eq!(decrypted_frame.message, original_message_bytes);

			Ok(())
		}
	}
}
