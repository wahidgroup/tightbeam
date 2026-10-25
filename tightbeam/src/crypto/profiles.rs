//! Security profiles and the cryptographic providers that run them, bound
//! through associated types.

#[cfg(all(not(feature = "std"), any(feature = "digest", feature = "signature")))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "aead"))]
use alloc::vec::Vec;
#[cfg(feature = "aead")]
use core::fmt;

use crate::der::asn1::ObjectIdentifier;
use crate::der::TagNumber;
use crate::wire::wire_sequence;

#[cfg(feature = "aead")]
use crate::crypto::aead::AeadAlgorithm;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::crypto::aead::Aes256Gcm;
#[cfg(all(feature = "aead", feature = "aes-gcm"))]
use crate::crypto::aead::Aes256GcmOid;
#[cfg(feature = "aead")]
use crate::crypto::common::generic_array::{ArrayLength, GenericArray};
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
#[cfg(all(feature = "digest", feature = "sha3"))]
use crate::crypto::hash::Sha3_256;
#[cfg(feature = "digest")]
use crate::crypto::hash::{CoreProxy, Digest, HashCore};
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

/// Implements [`KeyWrapAlgorithm`] for one house AES key wrap: its OID, its
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

			fn wrap(kek: &Kek<'_, Self>, key: &[u8]) -> Result<Vec<u8>, KeyError> {
				if key.len() < 16 || key.len() % 8 != 0 {
					return Err(KeyError::WrapLength((key.len(), 16).into()));
				}

				let wrapped = crate::crypto::aead::aes_kw::Kek::<$cipher>::new(kek.as_array()).wrap_vec(key);
				wrapped.map_err(KeyError::WrapFailed)
			}

			fn unwrap(kek: &Kek<'_, Self>, wrapped: &[u8]) -> Result<crate::ZeroizingBytes, KeyError> {
				let mut key = crate::ZeroizingBytes::default();
				key.resize(wrapped.len().saturating_sub(8), 0);
				Self::unwrap_into(kek, wrapped, &mut key)?;
				Ok(key)
			}

			fn unwrap_into(kek: &Kek<'_, Self>, wrapped: &[u8], out: &mut [u8]) -> Result<(), KeyError> {
				if wrapped.len() < 24 || wrapped.len() % 8 != 0 {
					return Err(KeyError::WrapLength((wrapped.len(), 24).into()));
				}

				// A wrapped key of n + 1 blocks holds a key of n blocks
				// (RFC 3394 §2.2.2), so `out` must have that size before the
				// key schedule runs.
				let key_len = wrapped.len().saturating_sub(8);
				if out.len() != key_len {
					return Err(KeyError::WrapLength((out.len(), key_len).into()));
				}

				let unwrapped = crate::crypto::aead::aes_kw::Kek::<$cipher>::new(kek.as_array()).unwrap(wrapped, out);
				unwrapped.map_err(KeyError::WrapFailed)
			}
		}
	};
}

/// Negotiation descriptor that holds only the OID set of a security profile.
///
/// Every field is an `Option`, and `None` means that the side that built it
/// has the feature of the algorithm disabled, which is `aead` for `key_wrap`.
///
/// Each field carries its own context tag, so every OID decodes into its own
/// field even when an earlier algorithm is absent.
///
/// The AEAD OID names the cipher, and the cipher type fixes the key length.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Beamable)]
pub struct SecurityProfileDesc {
	/// OID of the digest algorithm that the profile negotiates.
	pub digest: Option<ObjectIdentifier>,
	/// OID of the AEAD algorithm that the profile negotiates.
	pub aead: Option<ObjectIdentifier>,
	/// OID of the signature algorithm that the profile negotiates.
	pub signature: Option<ObjectIdentifier>,
	/// OID of the key derivation function that the profile negotiates.
	pub kdf: Option<ObjectIdentifier>,
	/// OID of the elliptic curve for key agreement.
	pub curve: Option<ObjectIdentifier>,
	/// OID of the key-wrap algorithm that the profile negotiates.
	pub key_wrap: Option<ObjectIdentifier>,
}

wire_sequence!(SecurityProfileDesc {
	digest: ctx(TagNumber::N0),
	aead: ctx(TagNumber::N1),
	signature: ctx(TagNumber::N2),
	kdf: ctx(TagNumber::N3),
	curve: ctx(TagNumber::N4),
	key_wrap: ctx(TagNumber::N5),
});

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

/// The strength of a runnable profile, as a [`ProfileStrengthPolicy`]
/// judges it.
///
/// The sizes come from the provider's types, so a policy judges the
/// algorithms the session runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ProfileStrength {
	/// The descriptor of the runnable profile.
	pub descriptor: SecurityProfileDesc,
	/// Key length in bytes of the provider's AEAD cipher.
	pub aead_key_bytes: usize,
	/// Output length in bytes of the provider's digest.
	pub digest_bytes: usize,
}

/// Minimum-strength filter a handshake endpoint applies to profiles.
///
/// The policy blocks downgrade (CWE-757), so an endpoint refuses a mutually
/// supported weak profile unless the policy admits it.
pub trait ProfileStrengthPolicy {
	/// Returns `true` when `strength` meets the policy floor.
	fn meets_floor(&self, strength: &ProfileStrength) -> bool;
}

/// The strength floor that [`CryptoProvider::strength_floor`] names unless a
/// provider overrides it.
///
/// # Requires
///
/// - The AEAD key size is at least 256 bits.
/// - The digest output is at least 256 bits.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::profiles::{DefaultCryptoProvider, DefaultStrengthFloor, ProfileStrengthPolicy};
/// use tightbeam::transport::handshake::negotiation::RunnableProfile;
///
/// // The house profile runs AES-256-GCM and SHA3-256.
/// let strength = RunnableProfile::<DefaultCryptoProvider>::native().strength();
/// assert!(DefaultStrengthFloor.meets_floor(&strength));
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultStrengthFloor;

/// Minimum AEAD key and digest output length in bytes, 256 bits each.
const DEFAULT_FLOOR_BYTES: usize = 32;

impl ProfileStrengthPolicy for DefaultStrengthFloor {
	fn meets_floor(&self, strength: &ProfileStrength) -> bool {
		let aead_ok = strength.aead_key_bytes >= DEFAULT_FLOOR_BYTES;
		let digest_ok = strength.digest_bytes >= DEFAULT_FLOOR_BYTES;
		aead_ok && digest_ok
	}
}

/// Strength policy that admits every profile.
///
/// This policy is the explicit opt-out of the minimum-strength floor. A
/// provider whose profile falls below [`DefaultStrengthFloor`] names this
/// policy from [`CryptoProvider::strength_floor`], and so does a
/// downgrade-attack test. Any other provider SHOULD keep
/// [`DefaultStrengthFloor`].
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::profiles::{DefaultCryptoProvider, NoStrengthFloor, ProfileStrengthPolicy};
/// use tightbeam::transport::handshake::negotiation::RunnableProfile;
///
/// let strength = RunnableProfile::<DefaultCryptoProvider>::native().strength();
/// assert!(NoStrengthFloor.meets_floor(&strength));
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct NoStrengthFloor;

impl ProfileStrengthPolicy for NoStrengthFloor {
	fn meets_floor(&self, _strength: &ProfileStrength) -> bool {
		true
	}
}

/// Metadata trait that declares only the algorithm identifiers (OIDs) of a
/// negotiated security profile. Concrete key types and implementations live
/// on [`CryptoProvider`].
///
/// # Rationale
///
/// - Peers negotiate over a compact [`SecurityProfileDesc`] of the hash,
///   AEAD, signature, key-wrap, KDF, and curve OIDs.
/// - The trait separates the identifiers a peer sees from the algorithm
///   types of [`CryptoProvider`] that run them at compile time.
/// - A dynamic dispatch or a plugin loader can use the trait with no change to the wire format.
/// - Peers must negotiate the KDF and the curve to interoperate. Two different
///   KDFs derive different keys from the same inputs, and the curve fixes the
///   group the ECDH runs in. Ed25519 signatures, for example, pair with X25519
///   for ECDH.
pub trait SecurityProfile {
	/// The negotiated digest algorithm. A [`CryptoProvider`] for this profile
	/// MUST use this type as its digest.
	#[cfg(feature = "digest")]
	type Digest: AssociatedOid;
	/// The negotiated AEAD algorithm identifier. A [`CryptoProvider`] for this
	/// profile MUST use a cipher that names this identifier.
	#[cfg(feature = "aead")]
	type AeadOid: AssociatedOid;
	/// The negotiated signature algorithm. A [`CryptoProvider`] for this
	/// profile MUST use this type as its signature.
	#[cfg(feature = "signature")]
	type SignatureAlg: SignatureAlgorithmIdentifier;
	/// The negotiated key derivation function. A [`CryptoProvider`] for this
	/// profile MUST use this type as its KDF.
	#[cfg(feature = "kdf")]
	type Kdf: AssociatedOid;
	/// The negotiated elliptic curve for key agreement. A [`CryptoProvider`]
	/// for this profile MUST use this type as its curve.
	#[cfg(feature = "ecdh")]
	type Curve: AssociatedOid;
	/// The negotiated key-wrap algorithm identifier. A [`CryptoProvider`] for
	/// this profile MUST use a key wrap that names this identifier.
	#[cfg(feature = "aead")]
	type KeyWrapOid: AssociatedOid;
}

/// Provider role for digest operations.
///
/// The role isolates digest operations from the full provider, so a bound
/// names only the digest and a test can target the digest alone. The digest
/// names its block size, the length HMAC pads its key to.
#[cfg(feature = "digest")]
pub trait DigestProvider {
	/// The digest algorithm. The keyed hashes of the key schedule drive its
	/// core ([`HashCore`]) with a buffer of their own.
	///
	/// The contract of the core is to wipe its state on drop: an HMAC over
	/// the core holds the key XOR `ipad` in that state (RFC 2104 § 2,
	/// NIST SP 800-56C Rev. 2 § 5.1). The house SHA3 cores keep that contract,
	/// and [`crate::crypto::hash`] asserts it at compile time.
	type Digest: Digest + AssociatedOid + BlockSizeUser + CoreProxy<Core: HashCore> + Clone + Default + Send + Sync;

	fn to_digest_algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: <Self::Digest as AssociatedOid>::OID, parameters: None }
	}

	/// A one-shot [`Digestor`] that digests its input under [`Self::Digest`].
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
	/// The AEAD cipher, which names the algorithm identifier and the key length
	/// the profile negotiates.
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
	/// requires it to be at least the key size of its AEAD, because the KEK
	/// must be at least as long as the content key it wraps (RFC 3565 §2.3.2).
	/// A [`Kek`] of this wrap holds a key of this size.
	type KekSize: ArrayLength<u8> + NonZero + IsLess<U65536, Output = B1>;

	/// Wrap `key` under `kek`.
	///
	/// # Errors
	///
	/// - [`KeyError::WrapLength`] -- `key` is shorter than two 64-bit blocks or
	///   is not a whole number of them.
	/// - [`KeyError::WrapFailed`] -- the wrap refused the key.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::profiles::{Aes128Wrap, Kek, KeyWrapAlgorithm};
	///
	/// // RFC 3394 §4.1: 128 bits of key data under a 128-bit KEK.
	/// let kek = 0x000102030405060708090a0b0c0d0e0f_u128.to_be_bytes();
	/// let kek = Kek::<Aes128Wrap>::try_from(kek.as_slice())?;
	/// let key_data = 0x00112233445566778899aabbccddeeff_u128.to_be_bytes();
	///
	/// let wrapped = Aes128Wrap::wrap(&kek, &key_data)?;
	/// let expected = [0x1fa68b0a8112b447_u64, 0xaef34bd8fb5a7b82, 0x9d3e862371d2cfe5].map(u64::to_be_bytes);
	/// assert_eq!(wrapped, expected.concat());
	/// # Ok::<(), tightbeam::crypto::key::KeyError>(())
	/// ```
	fn wrap(kek: &Kek<'_, Self>, key: &[u8]) -> Result<Vec<u8>, KeyError>;

	/// Unwrap `wrapped` under `kek`, whose integrity check refuses a key
	/// wrapped under another KEK or altered in flight (RFC 3394 §2.2.3).
	///
	/// # Errors
	///
	/// - [`KeyError::WrapLength`] -- `wrapped` is shorter than three 64-bit
	///   blocks or is not a whole number of them.
	/// - [`KeyError::WrapFailed`] -- `wrapped` fails the integrity check.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::profiles::{Aes128Wrap, Kek, KeyWrapAlgorithm};
	///
	/// // RFC 3394 §4.1: the wrapped key unwraps to 128 bits of key data.
	/// let kek = 0x000102030405060708090a0b0c0d0e0f_u128.to_be_bytes();
	/// let kek = Kek::<Aes128Wrap>::try_from(kek.as_slice())?;
	/// let wrapped = [0x1fa68b0a8112b447_u64, 0xaef34bd8fb5a7b82, 0x9d3e862371d2cfe5].map(u64::to_be_bytes);
	///
	/// let key_data = Aes128Wrap::unwrap(&kek, &wrapped.concat())?;
	/// assert_eq!(key_data.as_slice(), 0x00112233445566778899aabbccddeeff_u128.to_be_bytes());
	/// # Ok::<(), tightbeam::crypto::key::KeyError>(())
	/// ```
	fn unwrap(kek: &Kek<'_, Self>, wrapped: &[u8]) -> Result<crate::ZeroizingBytes, KeyError>;

	/// Unwrap `wrapped` under `kek` into `out`, which takes the unwrapped key
	/// whole, so a caller unwraps a content key onto its own stack.
	///
	/// The default unwraps through [`Self::unwrap`] and copies the key into
	/// `out`. The house AES wraps unwrap into `out` directly.
	///
	/// # Errors
	///
	/// - The errors of [`Self::unwrap`].
	/// - [`KeyError::WrapLength`] -- `out` differs in size from the unwrapped key.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::profiles::{Aes128Wrap, Kek, KeyWrapAlgorithm};
	///
	/// let kek = 0x000102030405060708090a0b0c0d0e0f_u128.to_be_bytes();
	/// let kek = Kek::<Aes128Wrap>::try_from(kek.as_slice())?;
	/// let wrapped = [0x1fa68b0a8112b447_u64, 0xaef34bd8fb5a7b82, 0x9d3e862371d2cfe5].map(u64::to_be_bytes);
	///
	/// // RFC 3394 §4.1: the buffer takes the 128 bits of key data whole.
	/// let mut key_data = [0u8; 16];
	/// Aes128Wrap::unwrap_into(&kek, &wrapped.concat(), &mut key_data)?;
	/// assert_eq!(key_data, 0x00112233445566778899aabbccddeeff_u128.to_be_bytes());
	/// # Ok::<(), tightbeam::crypto::key::KeyError>(())
	/// ```
	fn unwrap_into(kek: &Kek<'_, Self>, wrapped: &[u8], out: &mut [u8]) -> Result<(), KeyError> {
		let key = Self::unwrap(kek, wrapped)?;
		if key.len() != out.len() {
			return Err(KeyError::WrapLength((out.len(), key.len()).into()));
		}

		out.iter_mut().zip(key.iter()).for_each(|(slot, octet)| *slot = *octet);
		Ok(())
	}
}

/// A key-encryption key (KEK) of [`KeyWrapAlgorithm::KekSize`] octets for the
/// key wrap `W`, borrowed from the buffer that holds it.
///
/// [`TryFrom`] on a slice is its one length check, and [`From`] on an array
/// of [`KeyWrapAlgorithm::KekSize`] octets needs none, so each wrap and unwrap
/// under `W` receives a key of its size, and the length rule has one home.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::profiles::{Aes256Wrap, Kek, KeyWrapAlgorithm};
///
/// // AES-256 key wrap takes a 32-octet key and refuses a 16-octet one.
/// let key = [0x42u8; 32];
/// let kek = Kek::<Aes256Wrap>::try_from(key.as_slice())?;
/// assert!(Kek::<Aes256Wrap>::try_from(&key[..16]).is_err());
///
/// let wrapped = Aes256Wrap::wrap(&kek, &[0x11; 16])?;
/// let unwrapped = Aes256Wrap::unwrap(&kek, &wrapped)?;
/// assert_eq!(unwrapped.as_slice(), [0x11; 16].as_slice());
/// # Ok::<(), tightbeam::crypto::key::KeyError>(())
/// ```
#[cfg(feature = "aead")]
pub struct Kek<'a, W: KeyWrapAlgorithm + ?Sized> {
	/// The key, of the size of the wrap.
	key: &'a GenericArray<u8, W::KekSize>,
}

#[cfg(feature = "aead")]
impl<'a, W: KeyWrapAlgorithm + ?Sized> Kek<'a, W> {
	/// The octets of the key, which an implementation of `W` builds its key
	/// schedule from.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::profiles::{Aes128Wrap, Kek};
	///
	/// // The array holds the 16 octets of the key of AES-128 key wrap.
	/// let key = [0x42u8; 16];
	/// let kek = Kek::<Aes128Wrap>::try_from(key.as_slice())?;
	/// assert_eq!(kek.as_array().as_slice(), key.as_slice());
	/// # Ok::<(), tightbeam::crypto::key::KeyError>(())
	/// ```
	#[must_use]
	pub const fn as_array(&self) -> &'a GenericArray<u8, W::KekSize> {
		self.key
	}
}

/// A key whose array type holds the size of the wrap, so it needs no check.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::common::generic_array::GenericArray;
/// use tightbeam::crypto::profiles::{Aes256Wrap, Kek, KeyWrapAlgorithm};
///
/// // A holder of a typed array lends it with no length check to fail.
/// let key = GenericArray::from([0x42u8; 32]);
/// let kek = Kek::<Aes256Wrap>::from(&key);
///
/// let wrapped = Aes256Wrap::wrap(&kek, &[0x11; 16])?;
/// assert_eq!(wrapped.len(), 24);
/// # Ok::<(), tightbeam::crypto::key::KeyError>(())
/// ```
#[cfg(feature = "aead")]
impl<'a, W: KeyWrapAlgorithm + ?Sized> From<&'a GenericArray<u8, W::KekSize>> for Kek<'a, W> {
	fn from(key: &'a GenericArray<u8, W::KekSize>) -> Self {
		Self { key }
	}
}

/// The one length check of a key-encryption key.
#[cfg(feature = "aead")]
impl<'a, W: KeyWrapAlgorithm + ?Sized> TryFrom<&'a [u8]> for Kek<'a, W> {
	type Error = KeyError;

	/// The key that `key` holds.
	///
	/// # Errors
	///
	/// - [`KeyError::KekLength`] -- `key` is another length than [`KeyWrapAlgorithm::KekSize`].
	fn try_from(key: &'a [u8]) -> Result<Self, KeyError> {
		let expected = <W::KekSize as Unsigned>::USIZE;
		if key.len() != expected {
			return Err(KeyError::KekLength((key.len(), expected).into()));
		}

		// The check above refuses each other length, so the length that
		// `from_slice` asserts holds here.
		Ok(Self::from(GenericArray::from_slice(key)))
	}
}

/// A copy borrows the same key.
#[cfg(feature = "aead")]
impl<W: KeyWrapAlgorithm + ?Sized> Clone for Kek<'_, W> {
	fn clone(&self) -> Self {
		*self
	}
}

#[cfg(feature = "aead")]
impl<W: KeyWrapAlgorithm + ?Sized> Copy for Kek<'_, W> {}

/// The key stays out of the output.
#[cfg(feature = "aead")]
impl<W: KeyWrapAlgorithm + ?Sized> fmt::Debug for Kek<'_, W> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Kek").finish_non_exhaustive()
	}
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
/// The role isolates signature operations, so a type that only signs carries
/// fewer generic bounds.
///
/// The signature type parses its own encoding alone and names its canonical
/// form, which is DER `ECDSA-Sig-Value` with a low `s` for ECDSA.
#[cfg(feature = "signature")]
pub trait SigningProvider {
	/// The signature, which names its algorithm identifier and its canonical
	/// form.
	type Signature: SignatureEncoding + SignatureAlgorithmIdentifier + CanonicalForm + Send + Sync;
	/// The public key that verifies a [`Self::Signature`] over a prehash.
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
	/// The key derivation function, which names the algorithm identifier the
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
	/// The elliptic curve for key agreement, which names the algorithm
	/// identifier the profile negotiates.
	type Curve: Curve + CurveArithmetic + AssociatedOid;
}

/// Provider role for Key Encapsulation Mechanism (KEM) operations.
///
/// The role supports post-quantum and hybrid key agreement through the
/// RustCrypto `kem` traits. An application can supply a KEM implementation
/// for a hybrid classical and post-quantum protocol such as PQXDH.
#[cfg(feature = "kem")]
pub trait KemProvider {
	/// The encapsulated key that [`Self::Kem`] sends to its recipient.
	type EncappedKey: EncappedKey;
	/// The KEM, which encapsulates a shared secret into a
	/// [`Self::EncappedKey`] and decapsulates it.
	type Kem: Encapsulator<Self::EncappedKey> + Decapsulator<Self::EncappedKey> + Send + Sync;
}

/// Binds concrete implementations to the metadata in a [`SecurityProfile`].
///
/// This trait composes every provider role trait. A component can bound on
/// the role traits it uses, such as `SigningProvider + DigestProvider`, and so
/// avoid the full set of bounds that `CryptoProvider` carries.
///
/// # Profile binding
///
/// Each role's algorithm type MUST be the type its profile names. The bounds
/// enforce this, so a provider that runs one algorithm while its profile
/// negotiates another does not compile. The KEK of the key wrap is at least as
/// long as the AEAD key (RFC 3565 §2.3.2), so a provider that pairs
/// [`Aes128Wrap`] with AES-256-GCM does not compile either.
///
/// # Open roles
///
/// Every role is open: an implementor names its own type for any role, such
/// as a [`ContentEncryption`](crate::crypto::cms::ContentEncryption) cipher, a
/// [`KeyWrapAlgorithm`], or a KEM, and every layer that takes the provider
/// runs and requires that type.
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
	/// The profile this provider runs. Each algorithm it names is the type its
	/// role above uses.
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

	/// The strength floor every handshake of this provider holds its profile
	/// to, on each endpoint that runs the provider.
	///
	/// - The default is [`DefaultStrengthFloor`]: an AEAD key and a digest output of 256 bits or more.
	/// - A provider whose AEAD key or digest output is shorter runs a handshake
	///   only under a floor that admits its profile, such as
	///   [`NoStrengthFloor`], so it names that floor here (CWE-757).
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::profiles::{CryptoProvider, DefaultCryptoProvider, ProfileStrengthPolicy};
	/// use tightbeam::transport::handshake::negotiation::RunnableProfile;
	///
	/// // The house provider keeps the default floor, which its profile meets.
	/// let strength = RunnableProfile::<DefaultCryptoProvider>::native().strength();
	/// assert!(DefaultCryptoProvider::strength_floor().meets_floor(&strength));
	/// ```
	fn strength_floor() -> &'static (dyn ProfileStrengthPolicy + Send + Sync) {
		&DefaultStrengthFloor
	}
}

/// The key size of the AEAD of the provider `P`, as a `typenum` number.
///
/// [`CryptoProvider`] holds the KEK size of its key wrap at or above this
/// size, because the KEK must be at least as long as the content key it wraps
/// (RFC 3565 §2.3.2).
#[cfg(all(
	feature = "digest",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
pub type AeadKeySize<P> = <<P as AeadProvider>::AeadCipher as KeySizeUser>::KeySize;

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

/// The house provider, which runs [`TightbeamProfile`] and keeps the
/// [`DefaultStrengthFloor`].
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::constants::{
		TIGHTBEAM_ACK_KEY_ID_DOMAIN, TIGHTBEAM_CLIENT_FINISHED_DOMAIN, TIGHTBEAM_CLIENT_FINISHED_KEY_INFO,
		TIGHTBEAM_CLOSING_KDF_INFO, TIGHTBEAM_CLOSING_KEY_ID_DOMAIN, TIGHTBEAM_FRAME_UKM_LABEL,
		TIGHTBEAM_OPENING_UKM_LABEL, TIGHTBEAM_RECORD_KEY_ID_DOMAIN, TIGHTBEAM_SERVER_FINISHED_DOMAIN,
		TIGHTBEAM_SERVER_FINISHED_KEY_INFO, TIGHTBEAM_SESSION_KDF_INFO,
	};

	/// Guard the domain constants against accidental change.
	///
	/// A failure means that a domain constant changed, which invalidates every
	/// key and signature derived under the old value.
	#[test]
	fn test_domain_constants_stable() {
		assert_eq!(TIGHTBEAM_OPENING_UKM_LABEL, b"tb/handshake/opening/ukm/v1");
		assert_eq!(TIGHTBEAM_SESSION_KDF_INFO, b"tb/session/kdf/v1");
		assert_eq!(TIGHTBEAM_SERVER_FINISHED_DOMAIN, b"tb/handshake/finished/server/v1");
		assert_eq!(TIGHTBEAM_CLIENT_FINISHED_DOMAIN, b"tb/handshake/finished/client/v1");
		assert_eq!(TIGHTBEAM_ACK_KEY_ID_DOMAIN, b"tb/handshake/ack/kekid/v1");
		assert_eq!(TIGHTBEAM_FRAME_UKM_LABEL, b"tb/frame/ukm/v1");
		assert_eq!(TIGHTBEAM_RECORD_KEY_ID_DOMAIN, b"tb/session/record/kekid/v1");
		assert_eq!(TIGHTBEAM_CLOSING_KDF_INFO, b"tb/session/kdf/closing/v1");
		assert_eq!(TIGHTBEAM_CLOSING_KEY_ID_DOMAIN, b"tb/handshake/closing/kekid/v1");
		assert_eq!(TIGHTBEAM_CLIENT_FINISHED_KEY_INFO, b"tb/handshake/finished/client/mac/v1");
		assert_eq!(TIGHTBEAM_SERVER_FINISHED_KEY_INFO, b"tb/handshake/finished/server/mac/v1");
	}

	/// Each optional field carries its own tag, so every OID decodes into its
	/// own field when an algorithm before it is absent.
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
