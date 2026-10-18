//! Security profiles and the cryptographic providers that run them, bound
//! through associated types.

#[cfg(all(not(feature = "std"), any(feature = "digest", feature = "signature")))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "aead"))]
use alloc::vec::Vec;

use crate::der::asn1::ObjectIdentifier;
use crate::der::Sequence;

#[cfg(feature = "aead")]
use crate::crypto::aead::AeadAlgorithm;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::crypto::aead::Aes256Gcm;
#[cfg(all(feature = "aead", feature = "aes-gcm"))]
use crate::crypto::aead::Aes256GcmOid;
#[cfg(all(
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh",
	feature = "digest"
))]
use crate::crypto::common::typenum::IsGreaterOrEqual;
#[cfg(feature = "aead")]
use crate::crypto::common::typenum::{IsLess, NonZero, Unsigned, B1, U16, U24, U32, U65536};
#[cfg(feature = "digest")]
use crate::crypto::common::BlockSizeUser;
#[cfg(all(
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh",
	feature = "digest"
))]
use crate::crypto::common::KeySizeUser;
#[cfg(feature = "digest")]
use crate::crypto::hash::Digest;
#[cfg(all(feature = "digest", feature = "sha3"))]
use crate::crypto::hash::Sha3_256;
#[cfg(feature = "kdf")]
use crate::crypto::kdf::{HkdfSha3_256, KdfFunction};
#[cfg(feature = "aead")]
use crate::crypto::key::KeyError;
#[cfg(feature = "signature")]
use crate::crypto::sign::ecdsa::Secp256k1Signature;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::crypto::sign::ecdsa::Secp256k1VerifyingKey;
#[cfg(feature = "signature")]
use crate::crypto::sign::{CanonicalForm, PrehashVerifier, SignatureAlgorithmIdentifier, SignatureEncoding};
#[cfg(any(
	feature = "digest",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
use crate::der::oid::AssociatedOid;
#[cfg(feature = "aead")]
use crate::oids::{AES_128_WRAP, AES_192_WRAP, AES_256_WRAP};
#[cfg(any(feature = "digest", feature = "aead", feature = "signature"))]
use crate::spki::AlgorithmIdentifierOwned;
use crate::Beamable;
#[cfg(feature = "ecdh")]
use elliptic_curve::{Curve, CurveArithmetic};
#[cfg(feature = "kem")]
use kem::{Decapsulator, EncappedKey, Encapsulator};
/// A one-shot closure that verifies a signature over the given bytes against
/// a [`SignerInfo`](crate::SignerInfo).
#[cfg(feature = "signature")]
pub type SignatureVerifier<E = crate::TightBeamError> =
	Box<dyn FnOnce(&[u8], &crate::SignerInfo) -> core::result::Result<(), E>>;

/// A one-shot closure that digests the given bytes into a
/// [`DigestInfo`](crate::DigestInfo).
#[cfg(feature = "digest")]
pub type Digestor<E = crate::TightBeamError> = Box<dyn FnOnce(&[u8]) -> core::result::Result<crate::DigestInfo, E>>;

/// Implement [`KeyWrapAlgorithm`] for one house AES key wrap: its OID, its
/// key-encryption key size, and its cipher.
#[cfg(feature = "aead")]
macro_rules! impl_aes_key_wrap {
	($wrap:ty, $oid:expr, $cipher:ty, $size:ty) => {
		impl AssociatedOid for $wrap {
			const OID: ObjectIdentifier = $oid;
		}

		impl KeyWrapAlgorithm for $wrap {
			type Oid = Self;
			type KekSize = $size;

			fn wrap(kek: &[u8], key: &[u8]) -> Result<Vec<u8>, KeyError> {
				const SIZE: usize = <$size as Unsigned>::USIZE;
				let kek = <[u8; SIZE]>::try_from(kek).map_err(|_| KeyError::WrapLength((kek.len(), SIZE).into()))?;
				if key.len() < 16 || key.len() % 8 != 0 {
					return Err(KeyError::WrapLength((key.len(), 16).into()));
				}

				let wrapped = crate::crypto::aead::aes_kw::Kek::<$cipher>::from(kek).wrap_vec(key);
				wrapped.map_err(KeyError::WrapFailed)
			}

			fn unwrap(kek: &[u8], wrapped: &[u8]) -> Result<crate::ZeroizingBytes, KeyError> {
				const SIZE: usize = <$size as Unsigned>::USIZE;
				let kek = <[u8; SIZE]>::try_from(kek).map_err(|_| KeyError::WrapLength((kek.len(), SIZE).into()))?;
				if wrapped.len() < 24 || wrapped.len() % 8 != 0 {
					return Err(KeyError::WrapLength((wrapped.len(), 24).into()));
				}

				let key = crate::crypto::aead::aes_kw::Kek::<$cipher>::from(kek).unwrap_vec(wrapped);
				key.map(crate::ZeroizingBytes::new).map_err(KeyError::WrapFailed)
			}
		}
	};
}

/// Negotiation descriptor that holds only the OID set of a security profile.
///
/// Every field is an `Option`, and `None` means that the producing side has
/// the feature of the algorithm disabled, which is `aead` for `key_wrap`.
///
/// Each field carries its own context tag, so every OID decodes into its own
/// field even when an earlier algorithm is absent.
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
			#[cfg(feature = "aead")]
			key_wrap: Some(<P::KeyWrapOid as AssociatedOid>::OID),
			#[cfg(not(feature = "aead"))]
			key_wrap: None,
		}
	}
}

/// Metadata trait that declares only the algorithm identifiers (OIDs) of a
/// negotiated security profile. Concrete key types and implementations live
/// on `CryptoProvider`.
///
/// # Rationale
///
/// - Peers negotiate over a compact descriptor of the hash, AEAD, signature, key-wrap, KDF, and curve OIDs.
/// - The trait decouples the compile-time algorithm implementation
///   (`CryptoProvider`) from the protocol-visible identifiers
///   (`SecurityProfile`).
/// - A later dynamic dispatch or plugin loader can use the trait without a change to the wire format.
/// - Peers must negotiate the KDF and the curve to interoperate. Different KDFs
///   produce different keys from the same inputs, and the curve choice affects
///   ECDH operations. For example, Ed25519 signatures typically pair with
///   X25519 for ECDH.
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
	/// Key-wrap algorithm identifier. A [`CryptoProvider`] for this profile
	/// MUST use a key wrap that names this identifier.
	#[cfg(feature = "aead")]
	type KeyWrapOid: AssociatedOid;
}

/// Provider role for digest operations.
///
/// The role isolates digest operations from the full provider, so a bound
/// names only the digest and a test can target the digest alone. The digest
/// names its block size, which HMAC keys over.
#[cfg(feature = "digest")]
pub trait DigestProvider {
	type Digest: Digest + AssociatedOid + BlockSizeUser + Clone + Default + Send + Sync;

	fn to_digest_algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: <Self::Digest as AssociatedOid>::OID, parameters: None }
	}

	/// Convert this provider into a Digestor function.
	fn as_digestor<E>(&self) -> Digestor<E>
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
}

/// A key-wrap algorithm: its identifier type, the size of its
/// key-encryption key, and its wrap and unwrap of a content key (RFC 3394,
/// RFC 3565). An implementor brings its own wrap with an implementation of
/// this trait, and names it through [`KeyWrapProvider`].
#[cfg(feature = "aead")]
pub trait KeyWrapAlgorithm {
	/// The identifier type of the wrap, which a profile names.
	type Oid: AssociatedOid;

	/// The size in octets of the key-encryption key, as a `typenum` number in
	/// `1..=65535`, the range of `kekLength` (RFC 9629 §3). [`CryptoProvider`]
	/// requires it to be at least the key size of its AEAD, since the KEK must
	/// be at least as long as the content key it wraps (RFC 3565 §2.3.2).
	type KekSize: Unsigned + NonZero + IsLess<U65536, Output = B1>;

	/// Wrap `key` under `kek`.
	///
	/// # Errors
	///
	/// - [`KeyError::WrapLength`] -- `kek` is another size, or `key` is no whole number of 64-bit blocks.
	/// - [`KeyError::WrapFailed`] -- the wrap refused the key.
	fn wrap(kek: &[u8], key: &[u8]) -> Result<Vec<u8>, KeyError>;

	/// Unwrap `wrapped` under `kek`, whose integrity check refuses a key
	/// wrapped under another KEK or altered in flight (RFC 3394 §2.2.3).
	///
	/// # Errors
	///
	/// - [`KeyError::WrapLength`] -- `kek` or `wrapped` is another size.
	/// - [`KeyError::WrapFailed`] -- `wrapped` fails the integrity check.
	fn unwrap(kek: &[u8], wrapped: &[u8]) -> Result<crate::ZeroizingBytes, KeyError>;
}

/// Provider role for the key wrap of a content key.
///
/// The role names the wrap an envelope's recipient uses, and the wrap names
/// the identifier the profile negotiates.
#[cfg(feature = "aead")]
pub trait KeyWrapProvider {
	/// The key wrap, which names the identifier the profile negotiates.
	type KeyWrap: KeyWrapAlgorithm;
}

/// AES-128 key wrap, `id-aes128-wrap` (RFC 3565 §2.3.2).
#[cfg(feature = "aead")]
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes128Wrap;

/// AES-192 key wrap, `id-aes192-wrap` (RFC 3565 §2.3.2).
#[cfg(feature = "aead")]
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes192Wrap;

/// AES-256 key wrap, `id-aes256-wrap` (RFC 3565 §2.3.2), the house wrap.
#[cfg(feature = "aead")]
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes256Wrap;

#[cfg(feature = "aead")]
impl_aes_key_wrap!(Aes128Wrap, AES_128_WRAP, aes::Aes128, U16);
#[cfg(feature = "aead")]
impl_aes_key_wrap!(Aes192Wrap, AES_192_WRAP, aes::Aes192, U24);
#[cfg(feature = "aead")]
impl_aes_key_wrap!(Aes256Wrap, AES_256_WRAP, aes::Aes256, U32);

/// Provider role for signature generation and verification.
///
/// The role isolates signing operations, so a type that only signs carries
/// fewer generic bounds.
///
/// The signature type parses its own encoding alone and names its canonical
/// form, which is DER `ECDSA-Sig-Value` with a low `s` for ECDSA.
#[cfg(feature = "signature")]
pub trait SigningProvider {
	type Signature: SignatureEncoding + SignatureAlgorithmIdentifier + CanonicalForm + Send + Sync;
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
/// negotiates another does not compile. The KEK of the key wrap is at least as
/// long as the AEAD key (RFC 3565 §2.3.2), so a provider that pairs
/// [`Aes128Wrap`] with AES-256-GCM does not compile either.
///
/// # Bringing a part
///
/// Every role is open: an implementor names its own type for any role, such
/// as a `ContentEncryption` cipher, a [`KeyWrapAlgorithm`], or a KEM, and
/// every layer that takes the provider runs and requires that type.
#[cfg(all(
	feature = "digest",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
pub trait CryptoProvider:
	Default
	+ Copy
	+ DigestProvider
	+ AeadProvider
	+ KeyWrapProvider<KeyWrap: KeyWrapAlgorithm<KekSize: IsGreaterOrEqual<AeadKeySize<Self>, Output = B1>>>
	+ SigningProvider
	+ KdfProvider
	+ CurveProvider
{
	/// The profile this provider runs. Each algorithm it names is the type the
	/// matching role above uses.
	type Profile: SecurityProfile<
			Digest = Self::Digest,
			AeadOid = <Self::AeadCipher as AeadAlgorithm>::Oid,
			SignatureAlg = Self::Signature,
			Kdf = Self::Kdf,
			Curve = Self::Curve,
			KeyWrapOid = <Self::KeyWrap as KeyWrapAlgorithm>::Oid,
		> + Default;

	/// The KEM a `KEMRecipientInfo` of this provider encapsulates under. It
	/// names its own identifier, so an implementor brings its own KEM.
	#[cfg(all(feature = "hpke", feature = "signature"))]
	type Kem: crate::crypto::cms::RecipientKem;

	/// Return the profile this provider runs.
	fn profile(&self) -> &Self::Profile;
}

/// The key size of the AEAD of the provider `P`, as a `typenum` number.
///
/// [`CryptoProvider`] holds the KEK size of its key wrap at or above this
/// size, since the KEK must be at least as long as the content key it wraps
/// (RFC 3565 §2.3.2).
#[cfg(all(
	feature = "digest",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
pub type AeadKeySize<P> = <<P as AeadProvider>::AeadCipher as KeySizeUser>::KeySize;

/// Provider role for the HPKE single-shot seal (RFC 9180).
///
/// The role sits beside [`CryptoProvider`], so a provider on a curve that
/// has no HPKE suite still runs every other role.
#[cfg(all(
	feature = "digest",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh",
	feature = "hpke"
))]
pub trait HpkeProvider: CryptoProvider {
	/// The HPKE suite this provider seals under. Its curve, its KDFs, and its
	/// AEAD are the types the roles of [`CryptoProvider`] use, so the suite
	/// runs the algorithms the profile negotiates.
	type HpkeSuite: crate::crypto::hpke::HpkeSuite<
		Curve = Self::Curve,
		KemKdf = Self::Kdf,
		Kdf = Self::Kdf,
		Aead = Self::AeadCipher,
	>;
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
	#[cfg(feature = "aead")]
	type KeyWrapOid = Aes256Wrap;
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
impl KeyWrapProvider for DefaultCryptoProvider {
	type KeyWrap = Aes256Wrap;
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl SigningProvider for DefaultCryptoProvider {
	type Signature = Secp256k1Signature;
	type VerifyingKey = Secp256k1VerifyingKey;
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl KdfProvider for DefaultCryptoProvider {
	type Kdf = HkdfSha3_256;
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl CurveProvider for DefaultCryptoProvider {
	type Curve = k256::Secp256k1;
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl CryptoProvider for DefaultCryptoProvider {
	type Profile = TightbeamProfile;
	#[cfg(all(feature = "hpke", feature = "signature"))]
	type Kem = crate::crypto::hpke::DhKemSecp256k1;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

#[cfg(all(
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh",
	feature = "hpke"
))]
impl HpkeProvider for DefaultCryptoProvider {
	type HpkeSuite = crate::crypto::hpke::HpkeSecp256k1Sha3Aes256Gcm;
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::constants::{
		TIGHTBEAM_ACK_KEY_ID_DOMAIN, TIGHTBEAM_CLIENT_FINISHED_DOMAIN, TIGHTBEAM_HPKE_CLIENT_AUTH_DOMAIN,
		TIGHTBEAM_HPKE_FRAME_INFO, TIGHTBEAM_HPKE_HANDSHAKE_INFO, TIGHTBEAM_HPKE_SERVER_AUTH_DOMAIN,
		TIGHTBEAM_IDENTITY_KDF_INFO, TIGHTBEAM_IDENTITY_KEY_ID_DOMAIN, TIGHTBEAM_OPENING_UKM_LABEL,
		TIGHTBEAM_SERVER_FINISHED_DOMAIN, TIGHTBEAM_SESSION_KDF_INFO,
	};

	/// Guard the domain constants against accidental change.
	///
	/// A failure means that a domain constant changed, which invalidates every
	/// existing derived key and signature.
	#[test]
	fn test_domain_constants_stable() {
		assert_eq!(TIGHTBEAM_OPENING_UKM_LABEL, b"tb/handshake/opening/ukm/v1");
		assert_eq!(TIGHTBEAM_SESSION_KDF_INFO, b"tb/session/kdf/v1");
		assert_eq!(TIGHTBEAM_SERVER_FINISHED_DOMAIN, b"tb/handshake/finished/server/v1");
		assert_eq!(TIGHTBEAM_CLIENT_FINISHED_DOMAIN, b"tb/handshake/finished/client/v1");
		assert_eq!(TIGHTBEAM_ACK_KEY_ID_DOMAIN, b"tb/handshake/ack/kekid/v1");
		assert_eq!(TIGHTBEAM_HPKE_HANDSHAKE_INFO, b"tb/hpke/handshake/v2");
		assert_eq!(TIGHTBEAM_HPKE_FRAME_INFO, b"tb/hpke/frame/v1");
		assert_eq!(TIGHTBEAM_IDENTITY_KDF_INFO, b"tb/session/kdf/identity/v1");
		assert_eq!(TIGHTBEAM_IDENTITY_KEY_ID_DOMAIN, b"tb/handshake/identity/kekid/v1");
		assert_eq!(TIGHTBEAM_HPKE_CLIENT_AUTH_DOMAIN, b"tb/handshake/client-auth/hpke/v1");
		assert_eq!(TIGHTBEAM_HPKE_SERVER_AUTH_DOMAIN, b"tb/handshake/server-auth/hpke/v1");
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
			type KeyWrapOid = Aes256Wrap;
		}

		let desc = SecurityProfileDesc::from(&Aes128Profile);
		assert_eq!(desc.aead, Some(crate::crypto::aead::Aes128GcmOid::OID));
	}

	// The KDF and curve types carry the identifiers that peers negotiate, so
	// the default descriptor names `HKDF_SHA3_256` and `CURVE_SECP256K1`.
	#[cfg(all(feature = "kdf", feature = "ecdh"))]
	#[test]
	fn the_default_profile_negotiates_its_kdf_and_curve_identifiers() {
		let desc = SecurityProfileDesc::from(&TightbeamProfile);
		assert_eq!(desc.kdf, Some(crate::oids::HKDF_SHA3_256));
		assert_eq!(desc.curve, Some(crate::oids::CURVE_SECP256K1));
	}
}
