#[cfg(not(feature = "std"))]
extern crate alloc;

// Re-exports
#[cfg(feature = "zeroize")]
pub use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::TightBeamError;
use crate::AlgorithmIdentifier;
use crate::Result;

#[cfg(feature = "compress")]
use crate::CompressionInfo;
#[cfg(any(feature = "aead", feature = "digest", feature = "signature"))]
use crate::der::oid::AssociatedOid;
#[cfg(feature = "aead")]
use crate::EncryptionInfo;
#[cfg(feature = "digest")]
use crate::IntegrityInfo;
#[cfg(feature = "signature")]
use crate::SignatureInfo;

#[cfg(feature = "compress")]
pub type Inflator = Box<dyn FnOnce(&[u8], &CompressionInfo) -> Result<Vec<u8>>>;
#[cfg(feature = "compress")]
pub type Compressor = Box<dyn FnOnce(&[u8]) -> Result<(Vec<u8>, CompressionInfo)>>;
#[cfg(feature = "aead")]
pub type Encryptor = Box<dyn FnOnce(&[u8]) -> Result<(Vec<u8>, EncryptionInfo)>>;
#[cfg(feature = "aead")]
pub type Decryptor = Box<dyn FnOnce(&[u8], &EncryptionInfo) -> Result<Vec<u8>>>;
#[cfg(feature = "signature")]
pub type Signatory = Box<dyn FnOnce(&[u8]) -> Result<crate::SignatureInfo>>;
#[cfg(feature = "signature")]
pub type SignatureVerifier = Box<dyn FnOnce(&[u8], &crate::SignatureInfo) -> Result<()>>;
#[cfg(feature = "digest")]
pub type Digestor = Box<dyn FnOnce(&[u8]) -> Result<crate::IntegrityInfo>>;

#[cfg(feature = "digest")]
impl IntegrityInfo {
	/// Create a IntegrityInfo by computing a digest of the data using a RustCrypto
	/// Digest implementation.
	///
	/// # Security Note
	/// The hash is computed over the plaintext message before encryption.
	/// This allows integrity verification without requiring decryption keys,
	/// following the sign-then-encrypt pattern.
	pub fn digest<D>(data: impl AsRef<[u8]>) -> Result<Self>
	where
		D: digest::Digest + AssociatedOid,
	{
		let mut hasher = D::new();
		digest::Digest::update(&mut hasher, data.as_ref());
		let result = hasher.finalize();

		let algorithm = AlgorithmIdentifier { oid: D::OID, parameters: None };
		let digest = result.to_vec();
		Ok(Self { algorithm, parameters: digest })
	}

	pub fn compare(&self, hash: impl AsRef<[u8]>) -> bool {
		self.parameters.as_slice() == hash.as_ref()
	}
}

#[cfg(feature = "aead")]
impl EncryptionInfo {
	/// Create EncryptionInfo for an AEAD cipher with a nonce
	///
	/// # Security Warning
	/// **NEVER reuse a nonce with the same key!** Nonce reuse completely breaks
	/// AEAD security, allowing plaintext recovery and forgery attacks.
	pub fn prepare<C>(nonce: impl AsRef<[u8]>) -> Result<Self>
	where
		C: AssociatedOid,
	{
		let algorithm = AlgorithmIdentifier { oid: C::OID, parameters: None };
		let parameters = nonce.as_ref().to_vec();
		Ok(Self { algorithm, parameters })
	}
}

#[cfg(feature = "signature")]
impl SignatureInfo {
	/// Create SignatureInfo by signing data with a RustCrypto Signer.
	/// Requires a curve/algorithm type `C` that implements `AssociatedOid` (e.g., k256::Secp256k1).
	///
	/// # Security Note
	/// Follows the sign-then-encrypt pattern: signatures are computed over
	/// plaintext before encryption. This provides:
	/// - Non-repudiation (signature proves who created the message)
	/// - Authentication (verifiable without decryption keys)
	/// - Integrity (tampering detection)
	pub fn sign<C, S>(signer: &impl signature::Signer<S>, data: impl AsRef<[u8]>) -> Result<Self>
	where
		C: AssociatedOid,
		S: signature::SignatureEncoding,
	{
		let signature_bytes = signer.sign(data.as_ref());
		let signature_encoded = signature_bytes.to_vec();

		let signature_algorithm = AlgorithmIdentifier { oid: C::OID, parameters: None };
		let signature = signature_encoded.to_vec();
		Ok(Self { signature_algorithm, signature })
	}
}

#[cfg(feature = "secp256k1")]
impl TryFrom<SignatureInfo> for crate::crypto::sign::ecdsa::Secp256k1Signature {
	type Error = TightBeamError;

	fn try_from(info: SignatureInfo) -> core::result::Result<Self, Self::Error> {
		let bytes = info.signature.as_slice();
		Ok(crate::crypto::sign::ecdsa::Secp256k1Signature::from_slice(bytes)?)
	}
}

#[cfg(feature = "secp256k1")]
impl TryFrom<crate::crypto::sign::ecdsa::Secp256k1Signature> for SignatureInfo {
	type Error = TightBeamError;

	fn try_from(sig: crate::crypto::sign::ecdsa::Secp256k1Signature) -> core::result::Result<Self, Self::Error> {
		let oid = crate::crypto::sign::ecdsa::Secp256k1::OID;
		Ok(SignatureInfo {
			signature_algorithm: AlgorithmIdentifier { oid, parameters: None },
			signature: sig.to_vec(),
		})
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
		$crate::utils::compress($data, $crate::CompressionAlgorithm::$alg)
	}};
}

#[cfg(feature = "compress")]
#[macro_export]
macro_rules! decompress {
	($alg:ident, $data:expr) => {{
		$crate::utils::decompress($data, $crate::CompressionAlgorithm::$alg)
	}};
}

#[cfg(feature = "std")]
#[macro_export]
macro_rules! rwlock {
    // Single declaration with default
    ($name:ident: $ty:ty = $default:expr) => {
        const _: () = {
            static CELL: std::sync::OnceLock<std::sync::Arc<std::sync::RwLock<$ty>>> = std::sync::OnceLock::new();

            #[allow(non_snake_case)]
            pub(crate) fn $name() -> std::sync::Arc<std::sync::RwLock<$ty>> {
                CELL.get_or_init(|| std::sync::Arc::new(std::sync::RwLock::new($default)))
                    .clone()
            }
        };
    };

    // Single declaration without default (uses Default trait)
    ($name:ident: $ty:ty) => {
        const _: () = {
            static CELL: std::sync::OnceLock<std::sync::Arc<std::sync::RwLock<$ty>>> = std::sync::OnceLock::new();

            #[allow(non_snake_case)]
            pub(crate) fn $name() -> std::sync::Arc<std::sync::RwLock<$ty>> {
                CELL.get_or_init(|| std::sync::Arc::new(std::sync::RwLock::new(Default::default())))
                    .clone()
            }
        };
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
        const _: () = {
            static CELL: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<$ty>>> = std::sync::OnceLock::new();

            #[allow(non_snake_case)]
            pub(crate) fn $name() -> std::sync::Arc<std::sync::Mutex<$ty>> {
                CELL.get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new($default)))
                    .clone()
            }
        };
    };

    // Single declaration without default (uses Default trait)
    ($name:ident: $ty:ty) => {
        const _: () = {
            static CELL: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<$ty>>> = std::sync::OnceLock::new();

            #[allow(non_snake_case)]
            pub(crate) fn $name() -> std::sync::Arc<std::sync::Mutex<$ty>> {
                CELL.get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new(Default::default())))
                    .clone()
            }
        };
    };

    // Multiple declarations
    ($($name:ident: $ty:ty $(= $default:expr)?),+ $(,)?) => {
        $(
            $crate::mutex!($name: $ty $(= $default)?);
        )+
    };
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(not(feature = "std"))]
	use alloc::string::ToString;

	#[cfg(feature = "signature")]
	mod sign {
		use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
		use crate::crypto::sign::Signer;
		use crate::{SignatureInfo, Result};

		#[test]
		fn test_sign_macro() -> Result<()> {
			let secret_bytes = [1u8; 32];
			let signing_key = Secp256k1SigningKey::from_bytes(&secret_bytes.into())?;

			// Use a simple message type that can be DER encoded
			let data = crate::testing::TestMessage { content: "Test data for sign macro".to_string() };

			let signer = |bytes: &[u8]| -> Result<SignatureInfo> {
				let sig: Secp256k1Signature = signing_key.sign(bytes);
				SignatureInfo::try_from(sig)
			};

			let sig_info = sign!(signer, data)?;
			assert_eq!(sig_info.signature.len(), 64);

			Ok(())
		}
	}

	#[cfg(feature = "signature")]
	mod notarize {
		use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
		use crate::crypto::sign::Signer;
		use crate::{SignatureInfo, Result};

		#[test]
		fn test_notarize_macro() -> Result<()> {
			let mut tbs = crate::testing::create_v0_tightbeam(None, None);
			tbs.nonrepudiation = None; // Ensure no signature initially

			let secret_bytes = [1u8; 32];
			let signing_key = Secp256k1SigningKey::from_bytes(&secret_bytes.into())?;

			let signer = |bytes: &[u8]| -> Result<SignatureInfo> {
				let sig: Secp256k1Signature = signing_key.sign(bytes);
				SignatureInfo::try_from(sig)
			};

			let notarized = notarize!(tbs: tbs, position: nonrepudiation, signer: signer)?;
			assert!(notarized.nonrepudiation.is_some());

			Ok(())
		}
	}

	#[cfg(all(
		feature = "aead",
		feature = "aes-gcm",
		feature = "signature",
		feature = "secp256k1"
	))]
	mod validation {
		use crate::compose;
		use crate::crypto::aead::Aes256GcmOid;
		use crate::crypto::sign::ecdsa::{Secp256k1, Secp256k1Signature};
		use crate::testing::{
			create_test_cipher_key, create_test_signing_key, create_v0_tightbeam, ConfidentialNonrepudiableNote,
		};
		use crate::Version;

		#[test]
		fn test_confidential_nonrepudiable() {
			// Standard note should be fine
			let msg = create_v0_tightbeam(None, None);
			assert_eq!(msg.version, Version::V0);
			assert!(msg.metadata.confidentiality.is_none());
			assert!(msg.nonrepudiation.is_none());

			let msg = ConfidentialNonrepudiableNote { content: "secret".to_string() };

			// Build via macro without cipher
			let err = compose! {
				V1: id: "conf-no-enc",
					order: 0,
					message: msg.clone()
			}
			.expect_err("expected missing encryption error");
			assert!(matches!(err, tightbeam::TightBeamError::MissingEncryptionInfo));

			// Provide cipher: should fail without signer 
			let (_, cipher) = create_test_cipher_key();
			let err = compose! {
				V1: id: "conf-with-enc",
					order: 0,
					message: msg,
					confidentiality<Aes256GcmOid, _>: &cipher
			}
			.expect_err("expected missing signature error");
			assert!(matches!(err, tightbeam::TightBeamError::MissingSignatureInfo));

			// Provide signer: should succeed
			let signing_key = create_test_signing_key();
			let tb = compose! {
				V1: id: "conf-with-sig",
					order: 0,
					message: ConfidentialNonrepudiableNote { content: "another secret".to_string() },
					confidentiality<Aes256GcmOid, _>: &cipher,
					nonrepudiation<Secp256k1, Secp256k1Signature, _>: &signing_key
			}
			.expect("signing provided");
			assert_eq!(tb.version, Version::V1);
			assert!(tb.metadata.confidentiality.is_some());
			assert!(tb.nonrepudiation.is_some());
		}
	}

	#[cfg(feature = "secp256k1")]
	#[test]
	fn test_signature_info_sign() -> Result<()> {
		use signature::Verifier;

		use crate::crypto::sign::ecdsa::{Secp256k1, Secp256k1Signature, Secp256k1SigningKey};
		use crate::SignatureInfo;

		// Create a deterministic signing key from a fixed seed for testing
		let secret_bytes = [1u8; 32];
		let signing_key = Secp256k1SigningKey::from_bytes(&secret_bytes.into())?;
		// Test data to sign
		let data = b"Hello, TightBeam!";
		// Use the sign helper method with Secp256k1 as the curve type parameter
		let signature_info = SignatureInfo::sign::<Secp256k1, Secp256k1Signature>(&signing_key, data)?;

		// Verify the signature algorithm OID is set correctly (Secp256k1 curve OID)
		let algorithm = signature_info.signature_algorithm.oid.to_string();
		assert_eq!(algorithm, "1.3.132.0.10");

		// Verify the signature produces a correct length signature
		let length = signature_info.signature.len();
		assert_eq!(length, 64);

		// Verify the signature
		let verifying_key = signing_key.verifying_key();
		let signature = Secp256k1Signature::try_from(signature_info)?;
		let result = verifying_key.verify(data, &signature);
		assert!(result.is_ok());

		Ok(())
	}

	#[cfg(feature = "sha3")]
	#[test]
	fn test_hash_info_digest() {
		use crate::crypto::hash::Sha3_256;
		use crate::IntegrityInfo;

		// Test data to hash
		let data = b"Hello, TightBeam!";
		// Use the digest helper method with SHA3-256
		let hash_info = IntegrityInfo::digest::<Sha3_256>(data).unwrap();

		// Verify the hash algorithm OID is set correctly (SHA3-256 OID)
		let algorithm = hash_info.algorithm.oid.to_string();
		assert_eq!(algorithm, "2.16.840.1.101.3.4.2.8");

		// Verify the digest is not empty
		assert!(!hash_info.parameters.is_empty());

		// SHA3-256 produces a 32-byte hash
		let length = hash_info.parameters.len();
		assert_eq!(length, 32);
	}

	#[cfg(feature = "aes-gcm")]
	#[test]
	fn test_encryption_info_prepare() {
		use crate::crypto::aead::Aes256GcmOid;
		use crate::EncryptionInfo;

		// Create a nonce for AES-256-GCM (96 bits / 12 bytes)
		let nonce = [1u8; 12];
		// Use the prepare helper method
		let encryption_info = EncryptionInfo::prepare::<Aes256GcmOid>(&nonce).unwrap();

		// Verify the algorithm OID is set correctly (AES-256-GCM OID)
		let algorithm = encryption_info.algorithm.oid.to_string();
		assert_eq!(algorithm, "2.16.840.1.101.3.4.1.46");
		// Verify the nonce is stored correctly
		assert_eq!(encryption_info.parameters, &nonce);
		// Verify correct length
		assert_eq!(encryption_info.parameters.len(), 12);
	}
}
