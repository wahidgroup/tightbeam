//! Associated-type based cryptographic provider abstraction.

use crate::constants::TIGHTBEAM_UKM_PREFIX;
use crate::crypto::hash::Digest;
use crate::der::asn1::ObjectIdentifier;
use crate::der::oid::AssociatedOid;
use crate::der::Sequence;
use crate::oids::AES_256_WRAP;
use crate::spki::AlgorithmIdentifierOwned;
use crate::Beamable;

#[cfg(feature = "derive")]
use crate::Errorizable;

#[cfg(feature = "aead")]
use crate::crypto::aead::Aead;
#[cfg(all(feature = "aead", feature = "aes-gcm"))]
use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid};
#[cfg(feature = "ecdh")]
use crate::crypto::curves::Secp256k1Oid;
#[cfg(feature = "sha3")]
use crate::crypto::hash::Sha3_256;
#[cfg(feature = "kdf")]
use crate::crypto::kdf::{HkdfSha3_256, HkdfSha3_256Oid, KdfFunction};
#[cfg(feature = "kem")]
use crate::crypto::kem::{Decapsulator, EncappedKey, Encapsulator, Kyber1024Oid};
#[cfg(feature = "signature")]
use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
#[cfg(feature = "signature")]
use crate::crypto::sign::elliptic_curve::{Curve, CurveArithmetic};
#[cfg(feature = "signature")]
use crate::crypto::sign::{Signatory, SignatureAlgorithmIdentifier, SignatureEncoding};
#[cfg(feature = "transport")]
use crate::transport::handshake::HandshakeError;

/// Macro to generate key wrapper implementations.
/// Reduces duplication across AES-128/192/256 variants.
#[cfg(all(feature = "aead", feature = "transport"))]
macro_rules! impl_key_wrapper {
	($err:ty, $cipher:ty, $n:expr) => {
		Box::new(|cek: &[u8], kek: &[u8; $n]| {
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

/// Trait to extract key size from AEAD OID types.
///
/// This enables compile-time association between algorithm OIDs and their key sizes,
/// which is then captured in SecurityProfileDesc for runtime key derivation.
#[cfg(feature = "aead")]
pub trait AeadKeySize {
	const KEY_SIZE: usize;
}

/// AES-128-GCM key size (16 bytes)
#[cfg(feature = "aes-gcm")]
impl AeadKeySize for crate::crypto::aead::Aes128GcmOid {
	const KEY_SIZE: usize = 16;
}

/// AES-256-GCM key size (32 bytes)
#[cfg(feature = "aes-gcm")]
impl AeadKeySize for crate::crypto::aead::Aes256GcmOid {
	const KEY_SIZE: usize = 32;
}

/// Negotiation descriptor: pure OID set for a security profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Sequence)]
#[cfg_attr(feature = "derive", derive(Beamable))]
pub struct SecurityProfileDesc {
	pub digest: ObjectIdentifier,
	pub aead: Option<ObjectIdentifier>,
	pub aead_key_size: Option<u16>,
	pub signature: Option<ObjectIdentifier>,
	pub kdf: Option<ObjectIdentifier>,
	pub curve: Option<ObjectIdentifier>,
	pub key_wrap: Option<ObjectIdentifier>,
	pub kem: Option<ObjectIdentifier>,
}

impl<P: SecurityProfile> From<&P> for SecurityProfileDesc {
	fn from(_p: &P) -> Self {
		SecurityProfileDesc {
			#[cfg(feature = "digest")]
			digest: <P::DigestOid as AssociatedOid>::OID,
			#[cfg(not(feature = "digest"))]
			digest: ObjectIdentifier::new_unwrap("0.0.0.0"),
			#[cfg(feature = "aead")]
			aead: Some(<P::AeadOid as AssociatedOid>::OID),
			#[cfg(not(feature = "aead"))]
			aead: None,
			#[cfg(feature = "aead")]
			aead_key_size: Some(<P::AeadOid as AeadKeySize>::KEY_SIZE as u16),
			#[cfg(not(feature = "aead"))]
			aead_key_size: None,
			#[cfg(feature = "signature")]
			signature: Some(<P::SignatureAlg as SignatureAlgorithmIdentifier>::ALGORITHM_OID),
			#[cfg(not(feature = "signature"))]
			signature: None,
			#[cfg(feature = "kdf")]
			kdf: Some(<P::KdfOid as AssociatedOid>::OID),
			#[cfg(not(feature = "kdf"))]
			kdf: None,
			#[cfg(feature = "ecdh")]
			curve: Some(<P::CurveOid as AssociatedOid>::OID),
			#[cfg(not(feature = "ecdh"))]
			curve: None,
			key_wrap: P::KEY_WRAP_OID,
			#[cfg(feature = "kem")]
			kem: Some(<P::KemOid as AssociatedOid>::OID),
			#[cfg(not(feature = "kem"))]
			kem: None,
		}
	}
}

/// Pure metadata: declares only the algorithm identifiers (OIDs) that define the
/// negotiated security profile. No concrete key types or implementations.
///
/// Rationale:
/// - Allows negotiation over a compact descriptor (hash + aead + sig + wrap + kdf + curve + kem).
/// - Decouples compile-time algorithm implementation (CryptoProvider) from
///   protocol-visible identifiers (SecurityProfile).
/// - Enables future dynamic dispatch / plugin loading without changing wire format.
/// - KDF, curve, and KEM must be negotiated to ensure interoperability:
///   * Different KDFs produce different keys from the same inputs
///   * Curve choice affects ECDH operations (e.g., Ed25519 signatures typically use X25519 for ECDH)
///   * KEM choice enables hybrid classical+PQ key agreement (e.g., ECDH + Kyber-1024)
pub trait SecurityProfile {
	#[cfg(feature = "digest")]
	type DigestOid: AssociatedOid;
	#[cfg(feature = "aead")]
	type AeadOid: AssociatedOid + AeadKeySize;
	#[cfg(feature = "signature")]
	type SignatureAlg: SignatureAlgorithmIdentifier;
	#[cfg(feature = "kdf")]
	type KdfOid: AssociatedOid;
	#[cfg(feature = "ecdh")]
	type CurveOid: AssociatedOid;
	#[cfg(feature = "kem")]
	type KemOid: AssociatedOid;

	const KEY_WRAP_OID: Option<ObjectIdentifier> = None;
}

/// Provides digest/hash functionality.
///
/// This sub-trait isolates digest operations from the full provider,
/// making trait bounds clearer and enabling focused testing.
#[cfg(feature = "digest")]
pub trait DigestProvider {
	type Digest: Digest + AssociatedOid + Default + Send + Sync;

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
	type AeadCipher: Aead + Send + Sync;
	type AeadOid: AssociatedOid;

	fn to_aead_algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: <Self::AeadOid as AssociatedOid>::OID, parameters: None }
	}

	/// Convert this provider into a KeyWrapper function for AES-128 KEK (16 bytes).
	#[cfg(feature = "transport")]
	#[allow(clippy::type_complexity)]
	fn as_key_wrapper_16<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 16]) -> Result<Vec<u8>, E>>
	where
		E: From<HandshakeError>,
	{
		impl_key_wrapper!(E, aes::Aes128, 16)
	}

	/// Convert this provider into a KeyWrapper function for AES-192 KEK (24 bytes).
	#[cfg(feature = "transport")]
	#[allow(clippy::type_complexity)]
	fn as_key_wrapper_24<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 24]) -> Result<Vec<u8>, E>>
	where
		E: From<HandshakeError>,
	{
		impl_key_wrapper!(E, aes::Aes192, 24)
	}

	/// Convert this provider into a KeyWrapper function for AES-256 KEK (32 bytes).
	#[cfg(feature = "transport")]
	#[allow(clippy::type_complexity)]
	fn as_key_wrapper_32<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 32]) -> Result<Vec<u8>, E>>
	where
		E: From<HandshakeError>,
	{
		impl_key_wrapper!(E, aes::Aes256, 32)
	}

	/// Convert this provider into a KeyUnwrapper function for AES-128 KEK (16 bytes).
	///
	/// Used by recipients to unwrap (decrypt) wrapped content-encryption keys.
	#[cfg(feature = "transport")]
	#[allow(clippy::type_complexity)]
	fn as_key_unwrapper_16<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 16]) -> Result<Vec<u8>, E>>
	where
		E: From<HandshakeError>,
	{
		impl_key_unwrapper!(E, aes::Aes128, 16)
	}

	/// Convert this provider into a KeyUnwrapper function for AES-192 KEK (24 bytes).
	///
	/// Used by recipients to unwrap (decrypt) wrapped content-encryption keys.
	#[cfg(feature = "transport")]
	#[allow(clippy::type_complexity)]
	fn as_key_unwrapper_24<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 24]) -> Result<Vec<u8>, E>>
	where
		E: From<HandshakeError>,
	{
		impl_key_unwrapper!(E, aes::Aes192, 24)
	}

	/// Convert this provider into a KeyUnwrapper function for AES-256 KEK (32 bytes).
	///
	/// Used by recipients to unwrap (decrypt) wrapped content-encryption keys.
	#[cfg(feature = "transport")]
	#[allow(clippy::type_complexity)]
	fn as_key_unwrapper_32<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 32]) -> Result<Vec<u8>, E>>
	where
		E: From<HandshakeError>,
	{
		impl_key_unwrapper!(E, aes::Aes256, 32)
	}
}

/// Provides signature generation and verification.
///
/// Isolates signing operations to reduce generic bounds on types that only sign.
#[cfg(feature = "signature")]
pub trait SigningProvider {
	type Signature: SignatureEncoding + SignatureAlgorithmIdentifier + Send + Sync;
	type SigningKey: Signatory<Self::Signature>;
	type VerifyingKey: Send + Sync;

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
pub trait KdfProvider {
	type Kdf: KdfFunction;

	/// Convert this provider into a KeyDeriver function for a specific output length.
	///
	/// The output length is specified as a const generic parameter `N`.
	#[allow(clippy::type_complexity)]
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
	type Curve: Curve + CurveArithmetic;
	#[cfg(feature = "ecies")]
	type EciesMessage: crate::crypto::ecies::EciesMessageOps;
}

/// Provides Key Encapsulation Mechanism (KEM) operations.
///
/// Enables post-quantum and hybrid key agreement using RustCrypto's `kem` traits.
/// Applications can provide KEM implementations
/// to enable hybrid classical+PQ protocols like PQXDH.
#[cfg(feature = "kem")]
pub trait KemProvider {
	type EncappedKey: EncappedKey;
	type Kem: Encapsulator<Self::EncappedKey> + Decapsulator<Self::EncappedKey> + Send + Sync;
}

/// Binds concrete implementations to the metadata in a `SecurityProfile`.
///
/// This is a convenience trait that composes all role-based provider traits.
/// Components can use specific role traits (e.g., `SigningProvider + DigestProvider`)
/// instead of requiring the full `CryptoProvider` to reduce trait bound complexity.
// TODO RustCrypto currently does not support KEMs.
#[cfg(all(
	feature = "digest",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
pub trait CryptoProvider:
	Default + Copy + DigestProvider + AeadProvider + SigningProvider + KdfProvider + CurveProvider // + KemProvider
{
	type Profile: SecurityProfile + Default;
	fn profile(&self) -> &Self::Profile;
}

/// Default profile: requires confidentiality and non-repudiation.
/// Maps to numeric profile = 1.
#[derive(Debug, Default, Clone, Copy)]
pub struct TightbeamProfile;

impl SecurityProfile for TightbeamProfile {
	#[cfg(feature = "digest")]
	type DigestOid = Sha3_256;
	#[cfg(feature = "aead")]
	type AeadOid = Aes256GcmOid;
	#[cfg(feature = "signature")]
	type SignatureAlg = Secp256k1Signature;
	#[cfg(feature = "kdf")]
	type KdfOid = HkdfSha3_256Oid;
	#[cfg(feature = "ecdh")]
	type CurveOid = Secp256k1Oid;
	#[cfg(feature = "kem")]
	type KemOid = Kyber1024Oid;

	const KEY_WRAP_OID: Option<ObjectIdentifier> = Some(AES_256_WRAP);
}

#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultCryptoProvider {
	profile: TightbeamProfile,
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
impl KdfProvider for DefaultCryptoProvider {
	type Kdf = HkdfSha3_256;
}

#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
impl CurveProvider for DefaultCryptoProvider {
	type Curve = k256::Secp256k1;
	#[cfg(feature = "ecies")]
	type EciesMessage = crate::crypto::ecies::Secp256k1EciesMessage;
}

// TODO RustCrypto currently does not support KEMs.
// #[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
// impl KemProvider for DefaultCryptoProvider {
// 	type EncappedKey = Kyber1024EncappedKey;
// 	type Kem = Kyber1024;
// }

#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
impl CryptoProvider for DefaultCryptoProvider {
	type Profile = TightbeamProfile;

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

crate::impl_error_display!(UkmBuilderError {
	DuplicateTag { tag } => "Duplicate tag: {tag}",
	ExtensionTooLarge { tag, len } => "Extension too large (tag {tag} len {len})",
});

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
		let mut out = Vec::with_capacity(TIGHTBEAM_UKM_PREFIX.len() + 64 + ext_cap);
		out.extend_from_slice(TIGHTBEAM_UKM_PREFIX);
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
	use crate::constants::{
		TIGHTBEAM_KARI_KDF_INFO, TIGHTBEAM_SESSION_KDF_INFO, TIGHTBEAM_SIGNED_TRANSCRIPT_DOMAIN, TIGHTBEAM_UKM_PREFIX,
	};

	// ========================================================================
	// Domain Constant Stability Tests
	// ========================================================================

	/// Guard against accidental domain constant changes.
	/// If these assertions fail, it means domain constants were changed,
	/// which will invalidate all existing derived keys and signatures.
	#[test]
	fn test_domain_constants_stable() {
		assert_eq!(TIGHTBEAM_KARI_KDF_INFO, b"tb/kari/kdf/v1");
		assert_eq!(TIGHTBEAM_SESSION_KDF_INFO, b"tb/session/kdf/v1");
		assert_eq!(TIGHTBEAM_SIGNED_TRANSCRIPT_DOMAIN, b"tb/handshake/transcript/v1");
		assert_eq!(TIGHTBEAM_UKM_PREFIX, b"tb/kari/ukm/v1|");
	}

	/// Verify apply_domain prepends correctly.
	#[test]
	fn test_apply_domain() {
		let result = apply_domain(TIGHTBEAM_SESSION_KDF_INFO, b"test_material");
		assert!(result.starts_with(TIGHTBEAM_SESSION_KDF_INFO));
		assert!(result.ends_with(b"test_material"));
		assert_eq!(result.len(), TIGHTBEAM_SESSION_KDF_INFO.len() + b"test_material".len());
	}

	/// Changing a domain constant should produce different output.
	#[test]
	fn test_domain_separation_effectiveness() {
		let material = b"shared_material";
		let with_kari = apply_domain(TIGHTBEAM_KARI_KDF_INFO, material);
		let with_session = apply_domain(TIGHTBEAM_SESSION_KDF_INFO, material);
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
		assert!(ukm1.starts_with(TIGHTBEAM_UKM_PREFIX));
		assert_eq!(ukm1.len(), TIGHTBEAM_UKM_PREFIX.len() + 64);
	}

	#[test]
	fn ukm_extension_encoding() -> Result<(), Box<dyn std::error::Error>> {
		let c = nonce(1);
		let s = nonce(2);
		let ukm = UkmBuilder::new(c, s)
			.with_extension(0x01, b"hello")?
			.with_extension(0x02, b"world")?
			.finalize();

		// prefix + nonces + (tag+len+data)*2 = prefix + 64 + (1+2+5)*2 = prefix + 64 + 16
		assert_eq!(ukm.len(), TIGHTBEAM_UKM_PREFIX.len() + 64 + 16);
		let tail = &ukm[TIGHTBEAM_UKM_PREFIX.len() + 64..];
		assert_eq!(tail[0], 0x01);
		assert_eq!(&tail[1..3], &(5u16.to_be_bytes()));
		assert_eq!(&tail[3..8], b"hello");
		assert_eq!(tail[8], 0x02);
		assert_eq!(&tail[9..11], &(5u16.to_be_bytes()));
		assert_eq!(&tail[11..16], b"world");
		Ok(())
	}

	#[test]
	fn ukm_duplicate_tag_error() -> Result<(), Box<dyn std::error::Error>> {
		let c = nonce(3);
		let s = nonce(4);
		let mut b = UkmBuilder::new(c, s);
		assert!(b.add_extension(0x01, b"a").is_ok());

		let err = b.add_extension(0x01, b"b").unwrap_err();
		match err {
			UkmBuilderError::DuplicateTag { tag } => assert_eq!(tag, 0x01),
			_ => panic!("wrong error"),
		}

		Ok(())
	}

	#[test]
	fn ukm_extension_too_large_error() -> Result<(), Box<dyn std::error::Error>> {
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

		Ok(())
	}

	// =======================================================================
	// AEAD Key Size Tests
	// =======================================================================

	#[cfg(feature = "aes-gcm")]
	#[test]
	fn test_aes128_gcm_key_size() {
		use crate::crypto::aead::Aes128GcmOid;
		assert_eq!(<Aes128GcmOid as AeadKeySize>::KEY_SIZE, 16);
	}

	#[cfg(feature = "aes-gcm")]
	#[test]
	fn test_aes256_gcm_key_size() {
		use crate::crypto::aead::Aes256GcmOid;
		assert_eq!(<Aes256GcmOid as AeadKeySize>::KEY_SIZE, 32);
	}

	#[cfg(all(
		feature = "aes-gcm",
		feature = "secp256k1",
		feature = "sha3",
		feature = "kdf",
		feature = "kem"
	))]
	#[test]
	fn test_profile_descriptor_aes128() {
		// Define a test profile using AES-128-GCM
		#[derive(Debug, Default, Clone)]
		struct Aes128Profile;

		impl SecurityProfile for Aes128Profile {
			type DigestOid = crate::crypto::hash::Sha3_256;
			type AeadOid = crate::crypto::aead::Aes128GcmOid;
			type SignatureAlg = crate::crypto::sign::ecdsa::Secp256k1Signature;
			type KdfOid = crate::crypto::kdf::HkdfSha3_256Oid;
			type CurveOid = crate::crypto::curves::Secp256k1Oid;
			type KemOid = crate::crypto::kem::Kyber1024Oid;

			const KEY_WRAP_OID: Option<ObjectIdentifier> = Some(AES_256_WRAP);
		}

		// Verify the descriptor captures the 16-byte key size
		let profile = Aes128Profile;
		let desc = SecurityProfileDesc::from(&profile);
		assert_eq!(desc.aead_key_size, Some(16));
		assert_eq!(desc.aead, Some(crate::crypto::aead::Aes128GcmOid::OID));
	}
}
