//! Associated-type based cryptographic provider abstraction.

#[cfg(all(
	not(feature = "std"),
	any(
		feature = "digest",
		feature = "kdf",
		all(feature = "aead", feature = "transport")
	)
))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::constants::TIGHTBEAM_UKM_PREFIX;
use crate::der::asn1::ObjectIdentifier;
use crate::der::Sequence;
use crate::oids::AES_256_WRAP;

#[cfg(feature = "aead")]
use crate::crypto::aead::AeadAlgorithm;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::crypto::aead::Aes256Gcm;
#[cfg(all(feature = "aead", feature = "aes-gcm"))]
use crate::crypto::aead::Aes256GcmOid;
#[cfg(feature = "digest")]
use crate::crypto::hash::Digest;
#[cfg(all(feature = "digest", feature = "sha3"))]
use crate::crypto::hash::Sha3_256;
#[cfg(feature = "kdf")]
use crate::crypto::kdf::{HkdfSha3_256, KdfFunction};
#[cfg(feature = "kem")]
use crate::crypto::kem::{Decapsulator, EncappedKey, Encapsulator};
#[cfg(feature = "signature")]
use crate::crypto::sign::ecdsa::Secp256k1Signature;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::crypto::sign::ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey};
#[cfg(feature = "signature")]
use crate::crypto::sign::{PrehashVerifier, Signatory, SignatureAlgorithmIdentifier, SignatureEncoding};
#[cfg(any(
	feature = "digest",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
use crate::der::oid::AssociatedOid;
#[cfg(any(feature = "digest", feature = "aead", feature = "signature"))]
use crate::spki::AlgorithmIdentifierOwned;
#[cfg(feature = "transport")]
use crate::transport::handshake::HandshakeError;
use crate::Beamable;
use crate::Errorizable;
#[cfg(feature = "ecdh")]
use elliptic_curve::{Curve, CurveArithmetic};
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

/// Negotiation descriptor: pure OID set for a security profile.
///
/// Every field is `Option`: `None` uniformly means "algorithm not part of
/// this profile" (feature disabled on the producing side). Each field carries
/// its own context tag, so an absent algorithm cannot shift the next OID into
/// its place on decode.
///
/// The AEAD OID names the cipher, and the cipher type fixes the key length.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Sequence, Beamable)]
pub struct SecurityProfileDesc {
	/// Digest algorithm.
	#[asn1(context_specific = "0", optional = "true")]
	pub digest: Option<ObjectIdentifier>,
	/// AEAD algorithm.
	#[asn1(context_specific = "1", optional = "true")]
	pub aead: Option<ObjectIdentifier>,
	/// Signature algorithm.
	#[asn1(context_specific = "2", optional = "true")]
	pub signature: Option<ObjectIdentifier>,
	/// Key derivation function.
	#[asn1(context_specific = "3", optional = "true")]
	pub kdf: Option<ObjectIdentifier>,
	/// Elliptic curve for key agreement.
	#[asn1(context_specific = "4", optional = "true")]
	pub curve: Option<ObjectIdentifier>,
	/// Key-wrap algorithm.
	#[asn1(context_specific = "5", optional = "true")]
	pub key_wrap: Option<ObjectIdentifier>,
}

impl<P: SecurityProfile> From<&P> for SecurityProfileDesc {
	fn from(_p: &P) -> Self {
		SecurityProfileDesc {
			#[cfg(feature = "digest")]
			digest: Some(<P::Digest as AssociatedOid>::OID),
			#[cfg(not(feature = "digest"))]
			digest: None,
			#[cfg(feature = "aead")]
			aead: Some(<P::AeadOid as AssociatedOid>::OID),
			#[cfg(not(feature = "aead"))]
			aead: None,
			#[cfg(feature = "signature")]
			signature: Some(<P::SignatureAlg as SignatureAlgorithmIdentifier>::ALGORITHM_OID),
			#[cfg(not(feature = "signature"))]
			signature: None,
			#[cfg(feature = "kdf")]
			kdf: Some(<P::Kdf as AssociatedOid>::OID),
			#[cfg(not(feature = "kdf"))]
			kdf: None,
			#[cfg(feature = "ecdh")]
			curve: Some(<P::Curve as AssociatedOid>::OID),
			#[cfg(not(feature = "ecdh"))]
			curve: None,
			key_wrap: P::KEY_WRAP_OID,
		}
	}
}

/// Pure metadata: declares only the algorithm identifiers (OIDs) that define the
/// negotiated security profile. No concrete key types or implementations.
///
/// Rationale:
/// - Allows negotiation over a compact descriptor (hash + aead + sig + wrap + kdf + curve).
/// - Decouples compile-time algorithm implementation (CryptoProvider) from
///   protocol-visible identifiers (SecurityProfile).
/// - Enables future dynamic dispatch / plugin loading without changing wire format.
/// - KDF and curve must be negotiated to ensure interoperability:
///   * Different KDFs produce different keys from the same inputs
///   * Curve choice affects ECDH operations (e.g., Ed25519 signatures typically use X25519 for ECDH)
pub trait SecurityProfile {
	/// Digest algorithm. A [`CryptoProvider`] for this profile MUST use this
	/// type as its digest.
	#[cfg(feature = "digest")]
	type Digest: AssociatedOid;
	/// AEAD algorithm identifier. A [`CryptoProvider`] for this profile MUST
	/// use a cipher that names this identifier.
	#[cfg(feature = "aead")]
	type AeadOid: AssociatedOid;
	/// Signature algorithm. A [`CryptoProvider`] for this profile MUST use
	/// this type as its signature.
	#[cfg(feature = "signature")]
	type SignatureAlg: SignatureAlgorithmIdentifier;
	/// Key derivation function. A [`CryptoProvider`] for this profile MUST
	/// use this type as its KDF.
	#[cfg(feature = "kdf")]
	type Kdf: AssociatedOid;
	/// Elliptic curve for key agreement. A [`CryptoProvider`] for this
	/// profile MUST use this type as its curve.
	#[cfg(feature = "ecdh")]
	type Curve: AssociatedOid;

	/// Key-wrap algorithm, or [`None`] when the profile wraps no keys.
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
///
/// The cipher type names its own algorithm identifier through
/// [`AeadAlgorithm`].
#[cfg(feature = "aead")]
pub trait AeadProvider {
	/// AEAD cipher, which names the algorithm identifier and key length the
	/// profile negotiates.
	type AeadCipher: AeadAlgorithm + Send + Sync;

	fn to_aead_algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
		let oid = <<Self::AeadCipher as AeadAlgorithm>::Oid as AssociatedOid>::OID;
		AlgorithmIdentifierOwned { oid, parameters: None }
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
	type VerifyingKey: PrehashVerifier<Self::Signature> + Send + Sync;

	fn to_signature_algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned {
			oid: <Self::Signature as SignatureAlgorithmIdentifier>::ALGORITHM_OID,
			parameters: None,
		}
	}
}

/// Provides key derivation functionality.
///
/// Separates KDF operations (HKDF, etc.) for clearer trait bounds. The KDF
/// type names the algorithm identifier a peer negotiates for it.
#[cfg(feature = "kdf")]
pub trait KdfProvider {
	/// Key derivation function, which names the algorithm identifier the
	/// profile negotiates.
	type Kdf: KdfFunction + AssociatedOid;

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
/// Isolates curve-specific functionality (ECDH, key generation). The curve
/// type names the algorithm identifier a peer negotiates for it.
#[cfg(feature = "ecdh")]
pub trait CurveProvider {
	/// Elliptic curve for key agreement, which names the algorithm identifier
	/// the profile negotiates.
	type Curve: Curve + CurveArithmetic + AssociatedOid;
	#[cfg(feature = "ecies")]
	type EciesMessage: crate::crypto::ecies::EciesMessageOps;
}

/// Provides Key Encapsulation Mechanism (KEM) operations.
///
/// Enables post-quantum and hybrid key agreement using RustCrypto's `kem`
/// traits. Applications can provide KEM implementations to enable hybrid
/// classical+PQ protocols like PQXDH.
#[cfg(feature = "kem")]
pub trait KemProvider {
	type EncappedKey: EncappedKey;
	type Kem: Encapsulator<Self::EncappedKey> + Decapsulator<Self::EncappedKey> + Send + Sync;
}

/// Binds concrete implementations to the metadata in a `SecurityProfile`.
///
/// This trait composes all role-based provider traits. Components can use
/// specific role traits (e.g., `SigningProvider + DigestProvider`) instead of
/// requiring the full `CryptoProvider` to reduce trait bound complexity.
///
/// Each role's algorithm type MUST be the type its profile names. The bounds
/// enforce this, so a provider that runs one algorithm while its profile
/// negotiates another does not compile.
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
	/// The profile this provider runs. Each algorithm it names is the type the
	/// matching role above uses.
	type Profile: SecurityProfile<
			Digest = Self::Digest,
			AeadOid = <Self::AeadCipher as AeadAlgorithm>::Oid,
			SignatureAlg = Self::Signature,
			Kdf = Self::Kdf,
			Curve = Self::Curve,
		> + Default;

	/// The profile this provider runs.
	fn profile(&self) -> &Self::Profile;
}

/// The profile [`DefaultCryptoProvider`] runs: SHA3-256, AES-256-GCM, ECDSA
/// over secp256k1, HKDF-SHA3-256, and AES-256 key wrap.
#[derive(Debug, Default, Clone, Copy)]
pub struct TightbeamProfile;

impl SecurityProfile for TightbeamProfile {
	#[cfg(feature = "digest")]
	type Digest = Sha3_256;
	#[cfg(feature = "aead")]
	type AeadOid = Aes256GcmOid;
	#[cfg(feature = "signature")]
	type SignatureAlg = Secp256k1Signature;
	#[cfg(feature = "kdf")]
	type Kdf = HkdfSha3_256;
	#[cfg(feature = "ecdh")]
	type Curve = k256::Secp256k1;

	const KEY_WRAP_OID: Option<ObjectIdentifier> = Some(AES_256_WRAP);
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultCryptoProvider {
	profile: TightbeamProfile,
}

// Implement role traits for DefaultCryptoProvider
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl DigestProvider for DefaultCryptoProvider {
	type Digest = Sha3_256;
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl AeadProvider for DefaultCryptoProvider {
	type AeadCipher = Aes256Gcm;
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl SigningProvider for DefaultCryptoProvider {
	type Signature = Secp256k1Signature;
	type SigningKey = Secp256k1SigningKey;
	type VerifyingKey = Secp256k1VerifyingKey;
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl KdfProvider for DefaultCryptoProvider {
	type Kdf = HkdfSha3_256;
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl CurveProvider for DefaultCryptoProvider {
	type Curve = k256::Secp256k1;
	#[cfg(feature = "ecies")]
	type EciesMessage = crate::crypto::ecies::Secp256k1EciesMessage;
}

// TODO: KEM wiring deferred - RustCrypto lacks stable KEM provider traits.
// #[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
// impl KemProvider for DefaultCryptoProvider {
// 	type EncappedKey = Kyber1024EncappedKey;
// 	type Kem = Kyber1024;
// }

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl CryptoProvider for DefaultCryptoProvider {
	type Profile = TightbeamProfile;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

#[derive(Errorizable, Debug, Clone)]
#[allow(unused_variables)]
pub enum UkmBuilderError {
	#[error("Duplicate tag: {tag}")]
	DuplicateTag { tag: u8 },
	#[error("Extension too large (tag {tag} len {len})")]
	ExtensionTooLarge { tag: u8, len: usize },
}

pub type UkmResult<T> = ::core::result::Result<T, UkmBuilderError>;

/// Named client/server nonces for [`UkmBuilder::new`].
///
/// Named fields prevent swapping the two same-typed `[u8; 32]` nonces at
/// the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UkmNonces {
	/// Client contribution to the UKM nonce pair.
	pub client: [u8; 32],
	/// Server contribution to the UKM nonce pair.
	pub server: [u8; 32],
}

#[derive(Debug, Default)]
pub struct UkmBuilder {
	client: [u8; 32],
	server: [u8; 32],
	extensions: Vec<(u8, Vec<u8>)>,
}

impl UkmBuilder {
	/// Takes [`UkmNonces`] so client and server contributions cannot be
	/// swapped by position.
	pub fn new(nonces: UkmNonces) -> Self {
		Self { client: nonces.client, server: nonces.server, extensions: Vec::new() }
	}

	/// `data` accepts any type that converts via `AsRef<[u8]>`.
	pub fn with_extension(mut self, tag: u8, data: impl AsRef<[u8]>) -> UkmResult<Self> {
		self.add_extension(tag, data)?;
		Ok(self)
	}

	/// `data` accepts any type that converts via `AsRef<[u8]>`.
	pub fn add_extension(&mut self, tag: u8, data: impl AsRef<[u8]>) -> UkmResult<()> {
		let data = data.as_ref();
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
		let ukm1 = UkmBuilder::new(UkmNonces { client: c, server: s }).finalize();
		let ukm2 = UkmBuilder::new(UkmNonces { client: c, server: s }).finalize();
		assert_eq!(ukm1, ukm2);
		assert!(ukm1.starts_with(TIGHTBEAM_UKM_PREFIX));
		assert_eq!(ukm1.len(), TIGHTBEAM_UKM_PREFIX.len() + 64);
	}

	/// Named nonce fields keep client and server bytes in wire order.
	#[test]
	fn ukm_nonces_named_fields_preserve_order() {
		let client = nonce(0x11);
		let server = nonce(0x22);
		let ukm = UkmBuilder::new(UkmNonces { client, server }).finalize();
		let body = &ukm[TIGHTBEAM_UKM_PREFIX.len()..];
		assert_eq!(&body[..32], &client);
		assert_eq!(&body[32..64], &server);
	}

	#[test]
	fn ukm_extension_accepts_byte_slices() -> Result<(), Box<dyn std::error::Error>> {
		let owned = vec![1u8, 2, 3];
		let ukm = UkmBuilder::new(UkmNonces { client: nonce(7), server: nonce(8) })
			.with_extension(0x10, owned.as_slice())?
			.finalize();

		let tail = &ukm[TIGHTBEAM_UKM_PREFIX.len() + 64..];
		assert_eq!(tail[0], 0x10);
		assert_eq!(&tail[1..3], &(3u16.to_be_bytes()));
		assert_eq!(&tail[3..6], &[1, 2, 3]);
		Ok(())
	}

	#[test]
	fn ukm_extension_encoding() -> Result<(), Box<dyn std::error::Error>> {
		let c = nonce(1);
		let s = nonce(2);
		let ukm = UkmBuilder::new(UkmNonces { client: c, server: s })
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

		let mut b = UkmBuilder::new(UkmNonces { client: c, server: s });
		assert!(b.add_extension(0x01, b"a").is_ok());
		assert!(matches!(
			b.add_extension(0x01, b"b"),
			Err(UkmBuilderError::DuplicateTag { tag: 0x01 })
		));

		Ok(())
	}

	#[test]
	fn ukm_extension_too_large_error() -> Result<(), Box<dyn std::error::Error>> {
		let c = nonce(5);
		let s = nonce(6);

		let mut b = UkmBuilder::new(UkmNonces { client: c, server: s });
		let big = vec![0u8; (u16::MAX as usize) + 1];
		assert!(matches!(
			b.add_extension(0x02, &big),
			Err(UkmBuilderError::ExtensionTooLarge { tag: 0x02, len }) if len == big.len()
		));

		Ok(())
	}

	/// Each optional field carries its own tag, so an absent algorithm does not
	/// shift the next OID into its place.
	#[test]
	fn a_profile_with_absent_algorithms_round_trips() -> Result<(), Box<dyn std::error::Error>> {
		use crate::der::{Decode, Encode};

		let desc = SecurityProfileDesc {
			digest: None,
			aead: Some(crate::oids::AES_256_GCM),
			signature: None,
			kdf: None,
			curve: None,
			key_wrap: Some(AES_256_WRAP),
		};

		let decoded = SecurityProfileDesc::from_der(&desc.to_der()?)?;
		assert_eq!(decoded, desc);
		Ok(())
	}

	#[cfg(all(feature = "aes-gcm", feature = "secp256k1", feature = "sha3", feature = "kdf"))]
	#[test]
	fn a_profile_descriptor_names_its_aead() {
		#[derive(Debug, Default, Clone)]
		struct Aes128Profile;

		impl SecurityProfile for Aes128Profile {
			type Digest = crate::crypto::hash::Sha3_256;
			type AeadOid = crate::crypto::aead::Aes128GcmOid;
			type SignatureAlg = crate::crypto::sign::ecdsa::Secp256k1Signature;
			type Kdf = crate::crypto::kdf::HkdfSha3_256;
			type Curve = k256::Secp256k1;

			const KEY_WRAP_OID: Option<ObjectIdentifier> = Some(AES_256_WRAP);
		}

		let desc = SecurityProfileDesc::from(&Aes128Profile);
		assert_eq!(desc.aead, Some(crate::crypto::aead::Aes128GcmOid::OID));
	}

	// The KDF and curve types carry the identifiers peers already negotiate,
	// so the default descriptor keeps its wire values.
	#[cfg(all(feature = "kdf", feature = "ecdh"))]
	#[test]
	fn the_default_profile_negotiates_its_kdf_and_curve_identifiers() {
		let desc = SecurityProfileDesc::from(&TightbeamProfile);
		assert_eq!(desc.kdf, Some(crate::oids::HASH_SHA3_256));
		assert_eq!(desc.curve, Some(crate::oids::CURVE_SECP256K1));
	}
}
