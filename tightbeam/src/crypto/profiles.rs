//! Security profiles and the cryptographic providers that run them, bound
//! through associated types.

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
#[cfg(feature = "signature")]
use crate::crypto::sign::ecdsa::Secp256k1Signature;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::crypto::sign::ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey};
#[cfg(feature = "signature")]
use crate::crypto::sign::{LowSEncoding, PrehashVerifier, Signatory, SignatureAlgorithmIdentifier, SignatureEncoding};
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
#[cfg(feature = "kem")]
use kem::{Decapsulator, EncappedKey, Encapsulator};
/// Generate the AES key-wrap closure for one KEK size.
///
/// The AES-128, AES-192, and AES-256 variants share this body.
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

/// Generate the AES key-unwrap closure for one KEK size.
///
/// The AES-128, AES-192, and AES-256 variants share this body.
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

/// Negotiation descriptor that holds only the OID set of a security profile.
///
/// Every field is an `Option`, and `None` always means that the algorithm is
/// not part of this profile because the feature is disabled on the producing
/// side. Each field carries its own context tag, so an absent algorithm
/// cannot shift the next OID into its place on decode.
///
/// The AEAD OID names the cipher, and the cipher type fixes the key length.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Sequence, Beamable)]
pub struct SecurityProfileDesc {
	/// OID of the digest algorithm that the profile negotiates.
	#[asn1(context_specific = "0", optional = "true")]
	pub digest: Option<ObjectIdentifier>,
	/// OID of the AEAD algorithm that the profile negotiates.
	#[asn1(context_specific = "1", optional = "true")]
	pub aead: Option<ObjectIdentifier>,
	/// OID of the signature algorithm that the profile negotiates.
	#[asn1(context_specific = "2", optional = "true")]
	pub signature: Option<ObjectIdentifier>,
	/// OID of the key derivation function that the profile negotiates.
	#[asn1(context_specific = "3", optional = "true")]
	pub kdf: Option<ObjectIdentifier>,
	/// OID of the elliptic curve for key agreement.
	#[asn1(context_specific = "4", optional = "true")]
	pub curve: Option<ObjectIdentifier>,
	/// OID of the key-wrap algorithm that the profile negotiates.
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

/// Metadata trait that declares only the algorithm identifiers (OIDs) of a
/// negotiated security profile. Concrete key types and implementations live
/// on `CryptoProvider`.
///
/// # Rationale
///
/// - Peers negotiate over a compact descriptor of the hash, AEAD, signature,
///   key-wrap, KDF, and curve OIDs.
/// - The trait decouples the compile-time algorithm implementation
///   (`CryptoProvider`) from the protocol-visible identifiers
///   (`SecurityProfile`).
/// - A later dynamic dispatch or plugin loader can use the trait without a
///   change to the wire format.
/// - Peers must negotiate the KDF and the curve to interoperate: - Different
///   KDFs produce different keys from the same inputs. - The curve choice
///   affects ECDH operations. For example, Ed25519 signatures typically pair
///   with X25519 for ECDH.
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

/// Provider role for digest operations.
///
/// The role isolates digest operations from the full provider, so a bound
/// names only the digest and a test can target the digest alone.
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

/// Provider role for AEAD encryption and decryption.
///
/// The role separates AEAD operations from the other crypto primitives. The
/// cipher type names its own algorithm identifier through [`AeadAlgorithm`].
#[cfg(feature = "aead")]
pub trait AeadProvider {
	/// AEAD cipher, which names the algorithm identifier and key length the
	/// profile negotiates.
	type AeadCipher: AeadAlgorithm + Send + Sync;

	fn to_aead_algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
		let oid = <<Self::AeadCipher as AeadAlgorithm>::Oid as AssociatedOid>::OID;
		AlgorithmIdentifierOwned { oid, parameters: None }
	}

	/// Convert this provider into a `KeyWrapper` function for a 16-byte AES-128
	/// KEK.
	#[cfg(feature = "transport")]
	#[allow(clippy::type_complexity)]
	fn as_key_wrapper_16<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 16]) -> Result<Vec<u8>, E>>
	where
		E: From<HandshakeError>,
	{
		impl_key_wrapper!(E, aes::Aes128, 16)
	}

	/// Convert this provider into a `KeyWrapper` function for a 24-byte AES-192
	/// KEK.
	#[cfg(feature = "transport")]
	#[allow(clippy::type_complexity)]
	fn as_key_wrapper_24<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 24]) -> Result<Vec<u8>, E>>
	where
		E: From<HandshakeError>,
	{
		impl_key_wrapper!(E, aes::Aes192, 24)
	}

	/// Convert this provider into a `KeyWrapper` function for a 32-byte AES-256
	/// KEK.
	#[cfg(feature = "transport")]
	#[allow(clippy::type_complexity)]
	fn as_key_wrapper_32<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 32]) -> Result<Vec<u8>, E>>
	where
		E: From<HandshakeError>,
	{
		impl_key_wrapper!(E, aes::Aes256, 32)
	}

	/// Convert this provider into a `KeyUnwrapper` function for a 16-byte
	/// AES-128 KEK.
	///
	/// A recipient uses it to unwrap (decrypt) a wrapped content-encryption
	/// key.
	#[cfg(feature = "transport")]
	#[allow(clippy::type_complexity)]
	fn as_key_unwrapper_16<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 16]) -> Result<Vec<u8>, E>>
	where
		E: From<HandshakeError>,
	{
		impl_key_unwrapper!(E, aes::Aes128, 16)
	}

	/// Convert this provider into a `KeyUnwrapper` function for a 24-byte
	/// AES-192 KEK.
	///
	/// A recipient uses it to unwrap (decrypt) a wrapped content-encryption
	/// key.
	#[cfg(feature = "transport")]
	#[allow(clippy::type_complexity)]
	fn as_key_unwrapper_24<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 24]) -> Result<Vec<u8>, E>>
	where
		E: From<HandshakeError>,
	{
		impl_key_unwrapper!(E, aes::Aes192, 24)
	}

	/// Convert this provider into a `KeyUnwrapper` function for a 32-byte
	/// AES-256 KEK.
	///
	/// A recipient uses it to unwrap (decrypt) a wrapped content-encryption
	/// key.
	#[cfg(feature = "transport")]
	#[allow(clippy::type_complexity)]
	fn as_key_unwrapper_32<E>(&self) -> Box<dyn Fn(&[u8], &[u8; 32]) -> Result<Vec<u8>, E>>
	where
		E: From<HandshakeError>,
	{
		impl_key_unwrapper!(E, aes::Aes256, 32)
	}
}

/// Provider role for signature generation and verification.
///
/// The role isolates signing operations, so a type that only signs carries
/// fewer generic bounds.
#[cfg(feature = "signature")]
pub trait SigningProvider {
	type Signature: SignatureEncoding + SignatureAlgorithmIdentifier + LowSEncoding + Send + Sync;
	type SigningKey: Signatory<Self::Signature>;
	type VerifyingKey: PrehashVerifier<Self::Signature> + Send + Sync;

	fn to_signature_algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned {
			oid: <Self::Signature as SignatureAlgorithmIdentifier>::ALGORITHM_OID,
			parameters: None,
		}
	}
}

/// Provider role for key derivation.
///
/// The role separates KDF operations such as HKDF, so trait bounds stay
/// narrow. The KDF type names the algorithm identifier a peer negotiates for
/// it.
#[cfg(feature = "kdf")]
pub trait KdfProvider {
	/// Key derivation function, which names the algorithm identifier the
	/// profile negotiates.
	type Kdf: KdfFunction + AssociatedOid;
}

/// Provider role for elliptic curve operations.
///
/// The role isolates curve-specific operations such as ECDH and key
/// generation. The curve type names the algorithm identifier a peer
/// negotiates for it.
#[cfg(feature = "ecdh")]
pub trait CurveProvider {
	/// Elliptic curve for key agreement, which names the algorithm identifier
	/// the profile negotiates.
	type Curve: Curve + CurveArithmetic + AssociatedOid;
	/// ECIES wire message for this curve. A handshake holds one across an
	/// await, so it crosses threads.
	#[cfg(feature = "ecies")]
	type EciesMessage: crate::crypto::ecies::EciesMessageOps + Send + Sync + 'static;
}

/// Provider role for Key Encapsulation Mechanism (KEM) operations.
///
/// The role supports post-quantum and hybrid key agreement through the
/// RustCrypto `kem` traits. An application can supply a KEM implementation
/// for a hybrid classical and post-quantum protocol such as PQXDH.
#[cfg(feature = "kem")]
pub trait KemProvider {
	type EncappedKey: EncappedKey;
	type Kem: Encapsulator<Self::EncappedKey> + Decapsulator<Self::EncappedKey> + Send + Sync;
}

/// Binds concrete implementations to the metadata in a `SecurityProfile`.
///
/// This trait composes every provider role trait. A component can bound on
/// the role traits it uses, such as `SigningProvider + DigestProvider`, and so
/// avoid the trait bound complexity of the full `CryptoProvider`.
///
/// # Profile binding
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
	Default + Copy + DigestProvider + AeadProvider + SigningProvider + KdfProvider + CurveProvider
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

	/// Return the profile this provider runs.
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
	/// Start a UKM builder from the client and server nonces.
	///
	/// The builder takes [`UkmNonces`] so the client and server contributions
	/// cannot be swapped by position.
	pub fn new(nonces: UkmNonces) -> Self {
		Self { client: nonces.client, server: nonces.server, extensions: Vec::new() }
	}

	/// Add a tagged extension and return the builder.
	///
	/// [`UkmBuilder::add_extension`] lists the errors.
	pub fn with_extension(mut self, tag: u8, data: impl AsRef<[u8]>) -> UkmResult<Self> {
		self.add_extension(tag, data)?;
		Ok(self)
	}

	/// Add a tagged extension, which the UKM encodes as `tag | len(2) | data`.
	///
	/// # Errors
	///
	/// - [`UkmBuilderError::DuplicateTag`] -- the builder already holds `tag`.
	/// - [`UkmBuilderError::ExtensionTooLarge`] -- `data` is longer than `u16::MAX` bytes.
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
		// The output layout is:
		// TIGHTBEAM_UKM_PREFIX || client || server || [ tag | len(2) | data ]*
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::constants::{
		TIGHTBEAM_CLIENT_FINISHED_DOMAIN, TIGHTBEAM_KARI_KDF_INFO, TIGHTBEAM_SERVER_FINISHED_DOMAIN,
		TIGHTBEAM_SESSION_KDF_INFO, TIGHTBEAM_UKM_PREFIX,
	};

	/// Guard the domain constants against accidental change.
	///
	/// A failure means that a domain constant changed, which invalidates every
	/// existing derived key and signature.
	#[test]
	fn test_domain_constants_stable() {
		assert_eq!(TIGHTBEAM_KARI_KDF_INFO, b"tb/kari/kdf/v1");
		assert_eq!(TIGHTBEAM_SESSION_KDF_INFO, b"tb/session/kdf/v1");
		assert_eq!(TIGHTBEAM_SERVER_FINISHED_DOMAIN, b"tb/handshake/finished/server/v1");
		assert_eq!(TIGHTBEAM_CLIENT_FINISHED_DOMAIN, b"tb/handshake/finished/client/v1");
		assert_eq!(TIGHTBEAM_UKM_PREFIX, b"tb/kari/ukm/v1|");
	}

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

		// The length is prefix + nonces + (tag+len+data)*2, which is
		// prefix + 64 + (1+2+5)*2 = prefix + 64 + 16.
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
