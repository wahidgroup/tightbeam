//! Associated-type based cryptographic provider abstraction.

use crate::crypto::hash::Digest;
use crate::der::asn1::ObjectIdentifier;
use crate::der::oid::AssociatedOid;
use crate::spki::AlgorithmIdentifierOwned;

#[cfg(feature = "derive")]
use crate::Errorizable;

#[cfg(feature = "aead")]
use crate::crypto::aead::Aead;
#[cfg(all(feature = "aead", feature = "aes-gcm"))]
use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid};
#[cfg(feature = "sha3")]
use crate::crypto::hash::Sha3_256;
#[cfg(feature = "kdf")]
use crate::crypto::kdf::{HkdfSha3_256, KdfProvider};
#[cfg(feature = "signature")]
use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
#[cfg(feature = "signature")]
use crate::crypto::sign::{Signatory, SignatureAlgorithmIdentifier, SignatureEncoding};

/// Macro to generate key wrapper implementations.
/// Reduces duplication across AES-128/192/256 variants.
#[cfg(all(feature = "aead", feature = "transport"))]
macro_rules! impl_key_wrapper {
	($err:ty, $cipher:ty, $n:expr) => {
		Box::new(|cek: &[u8], kek: &[u8; $n]| {
			use crate::transport::handshake::HandshakeError;

			if cek.len() < 16 || cek.len() % 8 != 0 {
				return Err(<$err>::from(HandshakeError::InvalidKeySize {
					expected: 16,
					received: cek.len(),
				}));
			}

			crate::crypto::aead::aes_kw::Kek::<$cipher>::from(*kek)
				.wrap_vec(cek)
				.map_err(|_| <$err>::from(HandshakeError::InvalidKeySize { expected: 16, received: cek.len() }))
		})
	};
}

/// Macro to generate key unwrapper implementations.
/// Reduces duplication across AES-128/192/256 variants.
#[cfg(all(feature = "aead", feature = "transport"))]
macro_rules! impl_key_unwrapper {
	($err:ty, $cipher:ty, $n:expr) => {
		Box::new(|wrapped_cek: &[u8], kek: &[u8; $n]| {
			use crate::transport::handshake::HandshakeError;

			if wrapped_cek.len() < 24 || wrapped_cek.len() % 8 != 0 {
				return Err(<$err>::from(HandshakeError::InvalidKeySize {
					expected: 24,
					received: wrapped_cek.len(),
				}));
			}

			crate::crypto::aead::aes_kw::Kek::<$cipher>::from(*kek)
				.unwrap_vec(wrapped_cek)
				.map_err(|_| <$err>::from(HandshakeError::InvalidKeySize { expected: 24, received: wrapped_cek.len() }))
		})
	};
}

pub const DOMAIN_KARI_KDF: &[u8] = b"tb/kari/kdf/v1";
pub const DOMAIN_SESSION_KDF: &[u8] = b"tb/session/kdf/v1";
pub const DOMAIN_SIGNED_TRANSCRIPT: &[u8] = b"tb/handshake/transcript/v1";
pub const DOMAIN_UKM_PREFIX: &[u8] = b"tb/kari/ukm/v1|";

/// Trait to extract key size from AEAD OID types.
///
/// This enables compile-time association between algorithm OIDs and their key sizes,
/// which is then captured in SecurityProfileDesc for runtime key derivation.
#[cfg(feature = "aead")]
pub trait AeadKeySize {
	const KEY_SIZE: usize;
}

/// AES-256-GCM key size (32 bytes)
#[cfg(feature = "aes-gcm")]
impl AeadKeySize for crate::crypto::aead::Aes256GcmOid {
	const KEY_SIZE: usize = 32;
}

/// Negotiation descriptor: pure OID set for a security profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "derive", derive(crate::Beamable, crate::der::Sequence))]
pub struct SecurityProfileDesc {
	#[cfg(feature = "digest")]
	pub digest: ObjectIdentifier,
	#[cfg(feature = "aead")]
	pub aead: Option<ObjectIdentifier>,
	#[cfg(feature = "aead")]
	pub aead_key_size: Option<u16>,
	#[cfg(feature = "signature")]
	pub signature: Option<ObjectIdentifier>,
	pub key_wrap: Option<ObjectIdentifier>,
}

impl<P: SecurityProfile> From<&P> for SecurityProfileDesc {
	fn from(p: &P) -> Self {
		SecurityProfileDesc {
			digest: <P::DigestOid as AssociatedOid>::OID,
			#[cfg(feature = "aead")]
			aead: Some(<P::AeadOid as AssociatedOid>::OID),
			#[cfg(feature = "aead")]
			aead_key_size: Some(<P::AeadOid as AeadKeySize>::KEY_SIZE as u16),
			#[cfg(feature = "signature")]
			signature: Some(<P::SignatureAlg as SignatureAlgorithmIdentifier>::ALGORITHM_OID),
			key_wrap: p.key_wrap_oid(),
		}
	}
}

/// Pure metadata: declares only the algorithm identifiers (OIDs) that define the
/// negotiated security profile. No concrete key types or implementations.
///
/// Rationale:
/// - Allows negotiation over a compact descriptor (hash + aead + sig + wrap).
/// - Decouples compile-time algorithm implementation (CryptoProvider) from
///   protocol-visible identifiers (SecurityProfile).
/// - Enables future dynamic dispatch / plugin loading without changing wire format.
pub trait SecurityProfile {
	#[cfg(feature = "digest")]
	type DigestOid: AssociatedOid;
	#[cfg(feature = "aead")]
	type AeadOid: AssociatedOid + AeadKeySize;
	#[cfg(feature = "signature")]
	type SignatureAlg: SignatureAlgorithmIdentifier; // Provides ALGORITHM_OID

	fn key_wrap_oid(&self) -> Option<ObjectIdentifier> {
		None
	}
}

/// Provides digest/hash functionality.
///
/// This sub-trait isolates digest operations from the full provider,
/// making trait bounds clearer and enabling focused testing.
#[cfg(feature = "digest")]
pub trait DigestProvider {
	type Digest: Digest + AssociatedOid + Default;

	fn to_digest_algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: <Self::Digest as AssociatedOid>::OID, parameters: None }
	}

	/// Convert this provider into a Digestor function.
	fn as_digestor<E>(&self) -> crate::helpers::Digestor<E>
	where
		E: From<crate::TightBeamError>,
	{
		Box::new(|data: &[u8]| Ok(crate::utils::digest::<Self::Digest>(data)?))
	}
}

/// Provides AEAD cipher functionality.
///
/// Separates AEAD operations (encryption/decryption) from other crypto primitives.
#[cfg(feature = "aead")]
pub trait AeadProvider {
	type AeadCipher: Aead;
	type AeadOid: AssociatedOid;

	fn to_aead_algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: <Self::AeadOid as AssociatedOid>::OID, parameters: None }
	}

	/// Convert this provider into a KeyWrapper function for AES-128 KEK (16 bytes).
	#[cfg(feature = "transport")]
	fn as_key_wrapper_16<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 16]) -> Result<Vec<u8>, E>>
	where
		E: From<crate::transport::handshake::HandshakeError>,
	{
		impl_key_wrapper!(E, aes::Aes128, 16)
	}

	/// Convert this provider into a KeyWrapper function for AES-192 KEK (24 bytes).
	#[cfg(feature = "transport")]
	fn as_key_wrapper_24<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 24]) -> Result<Vec<u8>, E>>
	where
		E: From<crate::transport::handshake::HandshakeError>,
	{
		impl_key_wrapper!(E, aes::Aes192, 24)
	}

	/// Convert this provider into a KeyWrapper function for AES-256 KEK (32 bytes).
	#[cfg(feature = "transport")]
	fn as_key_wrapper_32<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 32]) -> Result<Vec<u8>, E>>
	where
		E: From<crate::transport::handshake::HandshakeError>,
	{
		impl_key_wrapper!(E, aes::Aes256, 32)
	}

	/// Convert this provider into a KeyUnwrapper function for AES-128 KEK (16 bytes).
	///
	/// Used by recipients to unwrap (decrypt) wrapped content-encryption keys.
	#[cfg(feature = "transport")]
	fn as_key_unwrapper_16<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 16]) -> Result<Vec<u8>, E>>
	where
		E: From<crate::transport::handshake::HandshakeError>,
	{
		impl_key_unwrapper!(E, aes::Aes128, 16)
	}

	/// Convert this provider into a KeyUnwrapper function for AES-192 KEK (24 bytes).
	///
	/// Used by recipients to unwrap (decrypt) wrapped content-encryption keys.
	#[cfg(feature = "transport")]
	fn as_key_unwrapper_24<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 24]) -> Result<Vec<u8>, E>>
	where
		E: From<crate::transport::handshake::HandshakeError>,
	{
		impl_key_unwrapper!(E, aes::Aes192, 24)
	}

	/// Convert this provider into a KeyUnwrapper function for AES-256 KEK (32 bytes).
	///
	/// Used by recipients to unwrap (decrypt) wrapped content-encryption keys.
	#[cfg(feature = "transport")]
	fn as_key_unwrapper_32<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 32]) -> Result<Vec<u8>, E>>
	where
		E: From<crate::transport::handshake::HandshakeError>,
	{
		impl_key_unwrapper!(E, aes::Aes256, 32)
	}
}

/// Provides signature generation and verification.
///
/// Isolates signing operations to reduce generic bounds on types that only sign.
#[cfg(feature = "signature")]
pub trait SigningProvider {
	type Signature: SignatureEncoding + SignatureAlgorithmIdentifier;
	type SigningKey: Signatory<Self::Signature>;
	type VerifyingKey;

	fn to_signature_algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned {
			oid: <Self::Signature as SignatureAlgorithmIdentifier>::ALGORITHM_OID,
			parameters: None,
		}
	}
}

/// Provides key derivation functionality.
///
/// Separates KDF operations (HKDF, etc.) for clearer trait bounds.
#[cfg(feature = "kdf")]
pub trait KdfProviderTrait {
	type Kdf: KdfProvider;

	/// Convert this provider into a KeyDeriver function for a specific output length.
	///
	/// The output length is specified as a const generic parameter `N`.
	/// Common sizes: 16 (AES-128), 24 (AES-192), 32 (AES-256), 48, 64
	///
	/// # Example
	/// ```ignore
	/// let provider = DefaultCryptoProvider::default();
	/// let deriver = provider.as_key_deriver::<HandshakeError, 32>(); // 32-byte keys
	/// let key = deriver(ikm, salt, info)?;
	/// ```
	fn as_key_deriver<E, const N: usize>(&self) -> Box<dyn Fn(&[u8], &[u8], &[u8]) -> Result<[u8; N], E>>
	where
		E: From<crate::crypto::kdf::KdfError>,
	{
		Box::new(|ikm: &[u8], salt: &[u8], info: &[u8]| {
			let arr = Self::Kdf::derive_key::<N>(ikm, info, Some(salt))?;
			Ok(*arr)
		})
	}
}

/// Provides elliptic curve operations.
///
/// Isolates curve-specific functionality (ECDH, key generation).
#[cfg(feature = "ecdh")]
pub trait CurveProvider {
	type Curve: elliptic_curve::Curve + elliptic_curve::CurveArithmetic;
}

/// Binds concrete implementations to the metadata in a `SecurityProfile`.
///
/// This is a convenience trait that composes all role-based provider traits.
/// Components can use specific role traits (e.g., `SigningProvider + DigestProvider`)
/// instead of requiring the full `CryptoProvider` to reduce trait bound complexity.
#[cfg(all(
	feature = "digest",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
pub trait CryptoProvider:
	Default + Clone + DigestProvider + AeadProvider + SigningProvider + KdfProviderTrait + CurveProvider
{
	type Profile: SecurityProfile + Default;
	fn profile(&self) -> &Self::Profile;
}

#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
#[derive(Debug, Default, Clone)]
pub struct DefaultSecurityProfile;

#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
impl SecurityProfile for DefaultSecurityProfile {
	#[cfg(feature = "digest")]
	type DigestOid = Sha3_256;
	#[cfg(feature = "aead")]
	type AeadOid = Aes256GcmOid;
	#[cfg(feature = "signature")]
	type SignatureAlg = Secp256k1Signature;

	fn key_wrap_oid(&self) -> Option<ObjectIdentifier> {
		Some(crate::asn1::AES_256_WRAP_OID)
	}
}

#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
#[derive(Debug, Default, Clone)]
pub struct DefaultCryptoProvider {
	profile: DefaultSecurityProfile,
}

// Implement role traits for DefaultCryptoProvider
#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
impl DigestProvider for DefaultCryptoProvider {
	type Digest = Sha3_256;
}

#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
impl AeadProvider for DefaultCryptoProvider {
	type AeadCipher = Aes256Gcm;
	type AeadOid = Aes256GcmOid;
}

#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
impl SigningProvider for DefaultCryptoProvider {
	type Signature = Secp256k1Signature;
	type SigningKey = Secp256k1SigningKey;
	type VerifyingKey = Secp256k1VerifyingKey;
}

#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
impl KdfProviderTrait for DefaultCryptoProvider {
	type Kdf = HkdfSha3_256;
}

#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
impl CurveProvider for DefaultCryptoProvider {
	type Curve = k256::Secp256k1;
}

#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
impl CryptoProvider for DefaultCryptoProvider {
	type Profile = DefaultSecurityProfile;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone)]
#[allow(unused_variables)]
pub enum UkmBuilderError {
	DuplicateTag { tag: u8 },
	ExtensionTooLarge { tag: u8, len: usize },
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for UkmBuilderError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			UkmBuilderError::DuplicateTag { tag } => write!(f, "Duplicate tag: {}", tag),
			UkmBuilderError::ExtensionTooLarge { tag, len } => {
				write!(f, "Extension too large (tag {} len {})", tag, len)
			}
		}
	}
}

pub type UkmResult<T> = ::core::result::Result<T, UkmBuilderError>;

#[derive(Debug, Default)]
pub struct UkmBuilder {
	client: [u8; 32],
	server: [u8; 32],
	extensions: Vec<(u8, Vec<u8>)>,
}

impl UkmBuilder {
	pub fn new(client: [u8; 32], server: [u8; 32]) -> Self {
		Self { client, server, extensions: Vec::new() }
	}

	pub fn with_extension(mut self, tag: u8, data: &[u8]) -> UkmResult<Self> {
		self.add_extension(tag, data)?;
		Ok(self)
	}

	pub fn add_extension(&mut self, tag: u8, data: &[u8]) -> UkmResult<()> {
		if self.extensions.iter().any(|(t, _)| *t == tag) {
			return Err(UkmBuilderError::DuplicateTag { tag });
		}
		if data.len() > u16::MAX as usize {
			return Err(UkmBuilderError::ExtensionTooLarge { tag, len: data.len() });
		}

		self.extensions.push((tag, data.to_vec()));
		Ok(())
	}

	pub fn finalize(self) -> Vec<u8> {
		// layout: DOMAIN_UKM_PREFIX || client || server || [ tag | len(2) | data ]*
		let ext_cap: usize = self.extensions.iter().map(|(_, d)| 1 + 2 + d.len()).sum();
		let mut out = Vec::with_capacity(DOMAIN_UKM_PREFIX.len() + 64 + ext_cap);
		out.extend_from_slice(DOMAIN_UKM_PREFIX);
		out.extend_from_slice(&self.client);
		out.extend_from_slice(&self.server);
		for (tag, data) in self.extensions.into_iter() {
			out.push(tag);
			let len = data.len() as u16;
			out.extend_from_slice(&len.to_be_bytes());
			out.extend_from_slice(&data);
		}
		out
	}
}

/// Helper to apply domain separation to key material.
///
/// Prepends a domain label to the material, ensuring KDF/signing operations
/// are context-bound and cannot be replayed across different protocol phases.
#[inline]
pub fn apply_domain(label: &[u8], material: &[u8]) -> Vec<u8> {
	let mut v = Vec::with_capacity(label.len() + material.len());
	v.extend_from_slice(label);
	v.extend_from_slice(material);
	v
}

#[cfg(test)]
mod tests {
	use super::*;

	// ========================================================================
	// Domain Constant Stability Tests
	// ========================================================================

	/// Guard against accidental domain constant changes.
	/// If these assertions fail, it means domain constants were changed,
	/// which will invalidate all existing derived keys and signatures.
	#[test]
	fn test_domain_constants_stable() {
		assert_eq!(DOMAIN_KARI_KDF, b"tb/kari/kdf/v1");
		assert_eq!(DOMAIN_SESSION_KDF, b"tb/session/kdf/v1");
		assert_eq!(DOMAIN_SIGNED_TRANSCRIPT, b"tb/handshake/transcript/v1");
		assert_eq!(DOMAIN_UKM_PREFIX, b"tb/kari/ukm/v1|");
	}

	/// Verify apply_domain prepends correctly.
	#[test]
	fn test_apply_domain() {
		let result = apply_domain(DOMAIN_SESSION_KDF, b"test_material");
		assert!(result.starts_with(DOMAIN_SESSION_KDF));
		assert!(result.ends_with(b"test_material"));
		assert_eq!(result.len(), DOMAIN_SESSION_KDF.len() + b"test_material".len());
	}

	/// Changing a domain constant should produce different output.
	#[test]
	fn test_domain_separation_effectiveness() {
		let material = b"shared_material";
		let with_kari = apply_domain(DOMAIN_KARI_KDF, material);
		let with_session = apply_domain(DOMAIN_SESSION_KDF, material);
		assert_ne!(with_kari, with_session, "Different domains must produce different outputs");
	}

	// =======================================================================
	// UKM Builder Tests
	// =======================================================================

	fn nonce(val: u8) -> [u8; 32] {
		let mut n = [val; 32];
		n[0] = val;
		n
	}

	#[test]
	fn ukm_basic_deterministic() {
		let c = nonce(0xAA);
		let s = nonce(0xBB);
		let ukm1 = UkmBuilder::new(c, s).finalize();
		let ukm2 = UkmBuilder::new(c, s).finalize();
		assert_eq!(ukm1, ukm2);
		assert!(ukm1.starts_with(DOMAIN_UKM_PREFIX));
		assert_eq!(ukm1.len(), DOMAIN_UKM_PREFIX.len() + 64);
	}

	#[test]
	fn ukm_extension_encoding() {
		let c = nonce(1);
		let s = nonce(2);
		let ukm = UkmBuilder::new(c, s)
			.with_extension(0x01, b"hello")
			.unwrap()
			.with_extension(0x02, b"world")
			.unwrap()
			.finalize();
		// prefix + nonces + (tag+len+data)*2 = prefix + 64 + (1+2+5)*2 = prefix + 64 + 16
		assert_eq!(ukm.len(), DOMAIN_UKM_PREFIX.len() + 64 + 16);
		let tail = &ukm[DOMAIN_UKM_PREFIX.len() + 64..];
		assert_eq!(tail[0], 0x01);
		assert_eq!(&tail[1..3], &(5u16.to_be_bytes()));
		assert_eq!(&tail[3..8], b"hello");
		assert_eq!(tail[8], 0x02);
		assert_eq!(&tail[9..11], &(5u16.to_be_bytes()));
		assert_eq!(&tail[11..16], b"world");
	}

	#[test]
	fn ukm_duplicate_tag_error() {
		let c = nonce(3);
		let s = nonce(4);
		let mut b = UkmBuilder::new(c, s);
		assert!(b.add_extension(0x01, b"a").is_ok());
		let err = b.add_extension(0x01, b"b").unwrap_err();
		match err {
			UkmBuilderError::DuplicateTag { tag } => assert_eq!(tag, 0x01),
			_ => panic!("wrong error"),
		}
	}

	#[test]
	fn ukm_extension_too_large_error() {
		let c = nonce(5);
		let s = nonce(6);
		let mut b = UkmBuilder::new(c, s);
		let big = vec![0u8; (u16::MAX as usize) + 1];
		let err = b.add_extension(0x02, &big).unwrap_err();
		match err {
			UkmBuilderError::ExtensionTooLarge { tag, len } => {
				assert_eq!(tag, 0x02);
				assert_eq!(len, big.len());
			}
			_ => panic!("wrong error"),
		}
	}
}
