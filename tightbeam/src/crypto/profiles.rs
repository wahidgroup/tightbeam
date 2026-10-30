//! The security profiles and the cryptographic providers that run them,
//! bound through associated types.

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
#[cfg(feature = "ecdh")]
use crate::crypto::exchange::{Ecdhe, KeyExchange};
#[cfg(all(feature = "preview-pqc", feature = "ecdh", feature = "sha3", feature = "kdf"))]
use crate::crypto::exchange::{Hybrid, Secp256k1MlKem768};
#[cfg(all(feature = "digest", feature = "sha3"))]
use crate::crypto::hash::Sha3_256;
#[cfg(feature = "digest")]
use crate::crypto::hash::{CoreProxy, Digest, HashCore};
#[cfg(all(feature = "hpke", feature = "signature"))]
use crate::crypto::hpke::DhKemSecp256k1;
#[cfg(all(feature = "kem", feature = "hpke", feature = "signature"))]
use crate::crypto::hpke::DhKemSecp256k1Enc;
#[cfg(feature = "kdf")]
use crate::crypto::kdf::{HkdfSha3_256, KdfFunction};
#[cfg(feature = "aead")]
use crate::crypto::key::KeyError;
#[cfg(all(feature = "kem", feature = "hpke", feature = "signature"))]
use crate::crypto::key::Secp256k1KeyProvider;
#[cfg(feature = "signature")]
use crate::crypto::sign::ecdsa::Secp256k1Signature;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::crypto::sign::ecdsa::Secp256k1VerifyingKey;
#[cfg(feature = "signature")]
use crate::crypto::sign::{CanonicalForm, PrehashVerifier, SignatureAlgorithmIdentifier, SignatureEncoding};
#[cfg(all(feature = "kem", feature = "x509"))]
use crate::crypto::x509::ext::pkix::KeyUsages;
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

/// The negotiation descriptor that holds only the OIDs of a security profile.
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
	/// The OID of the digest algorithm that the profile negotiates.
	pub digest: Option<ObjectIdentifier>,
	/// The OID of the AEAD algorithm that the profile negotiates.
	pub aead: Option<ObjectIdentifier>,
	/// The OID of the signature algorithm that the profile negotiates.
	pub signature: Option<ObjectIdentifier>,
	/// The OID of the key derivation function that the profile negotiates.
	pub kdf: Option<ObjectIdentifier>,
	/// The OID of the key exchange that the profile negotiates. The house
	/// exchange names the OID of its curve.
	pub key_exchange: Option<ObjectIdentifier>,
	/// The OID of the key-wrap algorithm that the profile negotiates.
	pub key_wrap: Option<ObjectIdentifier>,
}

wire_sequence!(SecurityProfileDesc {
	digest: ctx(TagNumber::N0),
	aead: ctx(TagNumber::N1),
	signature: ctx(TagNumber::N2),
	kdf: ctx(TagNumber::N3),
	key_exchange: ctx(TagNumber::N4),
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
			key_exchange: Some(<P::KeyExchange as AssociatedOid>::OID),
			#[cfg(not(feature = "ecdh"))]
			key_exchange: None,
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
	/// The key length in bytes of the provider's AEAD cipher.
	pub aead_key_bytes: usize,
	/// The output length in bytes of the provider's digest.
	pub digest_bytes: usize,
	/// The security strength of the provider's key exchange, which bounds the
	/// strength of every session key.
	pub key_exchange: SecurityStrength,
}

/// A security strength in bits, as the "Security Strength" column of NIST
/// SP 800-57 Part 1 Rev. 5, Table 2, states it.
///
/// The bits stay private, and one constant names each row of the table, so a
/// key exchange rates itself by a row. Each kind of exchange reads its row
/// from its own standard:
///
/// - An elliptic-curve group rates by the size of the order of its base
///   point, as Table 2 states ([`Self::of_ecc_order`]).
/// - X25519 rates [`Self::BITS_128`], at its "~128-bit security level" (RFC 7748 §1).
/// - ML-KEM-512, -768, and -1024 rate 128, 192, and 256 bits, by their categories (FIPS 203 §8).
/// - A hybrid rates at its stronger part only when its combiner binds each
///   part's ciphertext and encapsulation key, and at its weaker part
///   otherwise (NIST SP 800-227 §4.6.3).
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::profiles::SecurityStrength;
///
/// // secp256k1 and P-256 have a 256-bit order, which Table 2 rates at 128.
/// assert_eq!(SecurityStrength::of_ecc_order(256), SecurityStrength::BITS_128);
/// assert!(SecurityStrength::BITS_112 < SecurityStrength::BITS_128);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecurityStrength(u16);

impl SecurityStrength {
	/// The row of 80 bits or fewer, below the 112 bits NIST SP 800-57 Part 1
	/// Rev. 5 requires to apply protection.
	pub const BITS_80: Self = Self(80);
	/// The row of 112 bits.
	pub const BITS_112: Self = Self(112);
	/// The row of 128 bits.
	pub const BITS_128: Self = Self(128);
	/// The row of 192 bits.
	pub const BITS_192: Self = Self(192);
	/// The row of 256 bits.
	pub const BITS_256: Self = Self(256);

	/// The bits of this strength.
	pub const fn bits(self) -> u16 {
		self.0
	}

	/// The row of an elliptic-curve key whose base point has an order of
	/// `order_bits` bits, as the ECC column of Table 2 states it: 224 to 255
	/// bits rate 112, 256 to 383 rate 128, 384 to 511 rate 192, and 512 or more
	/// rate 256.
	pub const fn of_ecc_order(order_bits: usize) -> Self {
		match order_bits {
			512.. => Self::BITS_256,
			384.. => Self::BITS_192,
			256.. => Self::BITS_128,
			224.. => Self::BITS_112,
			_ => Self::BITS_80,
		}
	}
}

/// The minimum-strength filter that a handshake endpoint applies to profiles.
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
/// - The key exchange rates 128 bits or more, so ECDH over P-192 or P-224 falls below the floor.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::profiles::{DefaultCryptoProvider, DefaultStrengthFloor, ProfileStrengthPolicy};
/// use tightbeam::transport::handshake::negotiation::RunnableProfile;
///
/// // The house profile runs AES-256-GCM, SHA3-256, and secp256k1.
/// let strength = RunnableProfile::<DefaultCryptoProvider>::native().strength();
/// assert!(DefaultStrengthFloor.meets_floor(&strength));
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultStrengthFloor;

/// The minimum length in bytes of the AEAD key and the digest output, 256
/// bits each.
const DEFAULT_FLOOR_BYTES: usize = 32;

/// The minimum strength of the key exchange.
const DEFAULT_FLOOR_STRENGTH: SecurityStrength = SecurityStrength::BITS_128;

impl ProfileStrengthPolicy for DefaultStrengthFloor {
	fn meets_floor(&self, strength: &ProfileStrength) -> bool {
		let aead_ok = strength.aead_key_bytes >= DEFAULT_FLOOR_BYTES;
		let digest_ok = strength.digest_bytes >= DEFAULT_FLOOR_BYTES;
		let exchange_ok = strength.key_exchange >= DEFAULT_FLOOR_STRENGTH;
		aead_ok && digest_ok && exchange_ok
	}
}

/// The strength policy that admits every profile.
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

/// The metadata trait that declares only the algorithm identifiers (OIDs) of a
/// negotiated security profile. Concrete key types and implementations live
/// on [`CryptoProvider`].
///
/// # Rationale
///
/// - Peers negotiate over a compact [`SecurityProfileDesc`] of the hash,
///   AEAD, signature, key-wrap, KDF, and key-exchange OIDs.
/// - The trait separates the identifiers a peer sees from the algorithm
///   types of [`CryptoProvider`] that run them at compile time.
/// - A dynamic dispatch or a plugin loader can use the trait with no change to the wire format.
/// - Peers must negotiate the KDF and the key exchange to interoperate. Two
///   different KDFs derive different keys from the same inputs, and the key
///   exchange fixes the shares both sides send. The signature role is
///   independent of the exchange, so Ed25519 signatures pair with X25519 or
///   with ML-KEM.
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
	/// The negotiated key exchange. A [`CryptoProvider`] for this profile MUST
	/// use this type as its key exchange.
	#[cfg(feature = "ecdh")]
	type KeyExchange: AssociatedOid;
	/// The negotiated key-wrap algorithm identifier. A [`CryptoProvider`] for
	/// this profile MUST use a key wrap that names this identifier.
	#[cfg(feature = "aead")]
	type KeyWrapOid: AssociatedOid;
}

/// The provider role for digest operations.
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

/// The provider role for AEAD encryption and decryption.
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

	/// Unwrap `wrapped` under `kek`. The integrity check of the unwrap refuses
	/// a key wrapped under another KEK or altered in flight (RFC 3394 §2.2.3).
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
	/// - [`KeyError::KekLength`] -- the length of `key` differs from [`KeyWrapAlgorithm::KekSize`].
	fn try_from(key: &'a [u8]) -> Result<Self, KeyError> {
		let expected = <W::KekSize as Unsigned>::USIZE;
		if key.len() != expected {
			return Err(KeyError::KekLength((key.len(), expected).into()));
		}

		// The check above refuses every other length, so the length that
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

/// The provider role for the key wrap of a content key.
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

/// The provider role for signature generation and verification.
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

/// The provider role for key derivation.
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

/// The provider role for the ephemeral key exchange of a handshake and of
/// each rekey.
///
/// The role isolates the exchange, so a signer on one curve pairs with an
/// exchange on another, or with an exchange on no curve, such as ML-KEM. The
/// exchange type names the algorithm identifier a peer negotiates for it.
#[cfg(feature = "ecdh")]
pub trait KeyExchangeProvider {
	/// The key exchange, which names the algorithm identifier the profile
	/// negotiates, such as [`Ecdhe`] over a curve.
	type KeyExchange: KeyExchange;
}

/// The provider role for a Key Encapsulation Mechanism (KEM) of the RustCrypto
/// `kem` traits, such as a post-quantum KEM:
///
/// - [`ProviderKem`](crate::crypto::cms::ProviderKem) runs it in a `KEMRecipientInfo` (RFC 9629 §3).
/// - A provider that names `ProviderKem<Self>` as its [`CryptoProvider::Kem`]
///   seals and opens every envelope under it.
/// - [`DefaultCryptoProvider`] names DHKEM(secp256k1, HKDF-SHA256) (RFC 9180 §4.1).
#[cfg(feature = "kem")]
pub trait KemProvider {
	/// The encapsulated key that [`Self::Kem`] sends to its recipient, which
	/// names the public key of the recipient and the size of the shared
	/// secret.
	type EncappedKey: EncappedKey;
	/// The KEM, which encapsulates a fresh shared secret into a
	/// [`Self::EncappedKey`] to the public key of a recipient.
	type Kem: Encapsulator<Self::EncappedKey> + Default + Send + Sync;
	/// The private key of a recipient, which decapsulates a
	/// [`Self::EncappedKey`] to the shared secret.
	type DecapsulationKey: Decapsulator<Self::EncappedKey> + Send + Sync;

	/// The `keyUsage` bit that the certificate profile of [`Self::Kem`]
	/// asserts on a recipient certificate: `keyAgreement` for a DHKEM over an
	/// `id-ecPublicKey` key (RFC 5480 §3), and `keyEncipherment` for ML-KEM
	/// (RFC 9935 §5, RFC 9629 §3).
	#[cfg(feature = "x509")]
	const USAGE: KeyUsages;
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
	+ KeyExchangeProvider
{
	/// The profile this provider runs. Each algorithm it names is the type its
	/// role above uses.
	type Profile: SecurityProfile<
			Digest = Self::Digest,
			AeadOid = <Self::AeadCipher as AeadAlgorithm>::Oid,
			SignatureAlg = Self::Signature,
			Kdf = Self::Kdf,
			KeyExchange = Self::KeyExchange,
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
	/// - The default is [`DefaultStrengthFloor`]: an AEAD key and a digest
	///   output of 256 bits or more, and a key exchange of 128-bit strength or
	///   more.
	/// - A provider whose AEAD key, digest output, or key exchange is weaker
	///   runs a handshake only under a floor that admits its profile, such as
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
/// and ECDH over secp256k1, HKDF-SHA3-256, and AES-256 key wrap.
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
	type KeyExchange = Ecdhe<k256::Secp256k1>;
	#[cfg(feature = "aead")]
	type KeyWrapOid = Aes256Wrap;
}

/// Implements every role of a house provider that holds its profile in a
/// `profile` field: SHA3-256, AES-256-GCM, AES-256 key wrap, ECDSA over
/// secp256k1, HKDF-SHA3-256, the key exchange `$exchange`, and
/// DHKEM(secp256k1, HKDF-SHA256) as its KEM, under the profile `$profile`.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
macro_rules! impl_house_provider {
	($provider:ty, $profile:ty, $exchange:ty) => {
		impl DigestProvider for $provider {
			type Digest = Sha3_256;
		}

		impl AeadProvider for $provider {
			type AeadCipher = Aes256Gcm;
		}

		impl KeyWrapProvider for $provider {
			type KeyWrap = Aes256Wrap;
		}

		impl SigningProvider for $provider {
			type Signature = Secp256k1Signature;
			type VerifyingKey = Secp256k1VerifyingKey;
		}

		impl KdfProvider for $provider {
			type Kdf = HkdfSha3_256;
		}

		impl KeyExchangeProvider for $provider {
			type KeyExchange = $exchange;
		}

		/// The house KEM role: DHKEM(secp256k1, HKDF-SHA256) under the
		/// RustCrypto `kem` traits, whose recipient key is a
		/// [`Secp256k1KeyProvider`].
		#[cfg(all(feature = "kem", feature = "hpke"))]
		impl KemProvider for $provider {
			type EncappedKey = DhKemSecp256k1Enc;
			type Kem = DhKemSecp256k1;
			type DecapsulationKey = Secp256k1KeyProvider;

			const USAGE: KeyUsages = KeyUsages::KeyAgreement;
		}

		impl CryptoProvider for $provider {
			type Profile = $profile;
			#[cfg(feature = "hpke")]
			type Kem = DhKemSecp256k1;

			fn profile(&self) -> &Self::Profile {
				&self.profile
			}
		}
	};
}

/// The house provider, which runs [`TightbeamProfile`] and keeps the
/// [`DefaultStrengthFloor`].
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultCryptoProvider {
	profile: TightbeamProfile,
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl_house_provider!(DefaultCryptoProvider, TightbeamProfile, Ecdhe<k256::Secp256k1>);

/// The profile [`PreviewPqcProvider`] runs: the algorithms of
/// [`TightbeamProfile`], with the hybrid of ML-KEM-768 and ECDH over
/// secp256k1 as its key exchange.
#[cfg(all(feature = "preview-pqc", feature = "ecdh", feature = "sha3", feature = "kdf"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct PreviewPqcProfile;

#[cfg(all(feature = "preview-pqc", feature = "ecdh", feature = "sha3", feature = "kdf"))]
impl SecurityProfile for PreviewPqcProfile {
	#[cfg(feature = "digest")]
	type Digest = Sha3_256;
	#[cfg(feature = "aead")]
	type AeadOid = Aes256GcmOid;
	#[cfg(feature = "signature")]
	type SignatureAlg = Secp256k1Signature;
	type Kdf = HkdfSha3_256;
	type KeyExchange = Hybrid<Secp256k1MlKem768>;
	#[cfg(feature = "aead")]
	type KeyWrapOid = Aes256Wrap;
}

/// The house provider with a post-quantum key exchange: it runs
/// [`PreviewPqcProfile`] and keeps the [`DefaultStrengthFloor`]. Its envelope
/// KEM is the KEM of [`DefaultCryptoProvider`].
#[cfg(all(
	feature = "preview-pqc",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
#[derive(Debug, Default, Clone, Copy)]
pub struct PreviewPqcProvider {
	profile: PreviewPqcProfile,
}

#[cfg(all(
	feature = "preview-pqc",
	feature = "aead",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
impl_house_provider!(PreviewPqcProvider, PreviewPqcProfile, Hybrid<Secp256k1MlKem768>);

#[cfg(test)]
mod tests {
	use super::*;
	use crate::constants::{
		TIGHTBEAM_ACK_KEY_ID_DOMAIN, TIGHTBEAM_CLIENT_FINISHED_DOMAIN, TIGHTBEAM_CLIENT_FINISHED_KEY_INFO,
		TIGHTBEAM_CLOSING_KDF_INFO, TIGHTBEAM_CLOSING_KEY_ID_DOMAIN, TIGHTBEAM_FRAME_UKM_LABEL,
		TIGHTBEAM_HYBRID_EXCHANGE_LABEL, TIGHTBEAM_OPENING_UKM_LABEL, TIGHTBEAM_RECORD_KEY_ID_DOMAIN,
		TIGHTBEAM_SERVER_FINISHED_DOMAIN, TIGHTBEAM_SERVER_FINISHED_KEY_INFO, TIGHTBEAM_SESSION_KDF_INFO,
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
		assert_eq!(TIGHTBEAM_HYBRID_EXCHANGE_LABEL, b"tb/exchange/hybrid/v1");
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
			key_exchange: None,
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
			type KeyExchange = Ecdhe<k256::Secp256k1>;
			type KeyWrapOid = Aes256Wrap;
		}

		let desc = SecurityProfileDesc::from(&Aes128Profile);
		assert_eq!(desc.aead, Some(crate::crypto::aead::Aes128GcmOid::OID));
	}

	// The KDF and key-exchange types carry the identifiers that peers
	// negotiate, so the default descriptor names `HKDF_SHA3_256` and
	// `CURVE_SECP256K1`.
	#[cfg(all(feature = "kdf", feature = "ecdh"))]
	#[test]
	fn the_default_profile_negotiates_its_kdf_and_key_exchange_identifiers() {
		let desc = SecurityProfileDesc::from(&TightbeamProfile);
		assert_eq!(desc.kdf, Some(crate::oids::HKDF_SHA3_256));
		assert_eq!(desc.key_exchange, Some(crate::oids::CURVE_SECP256K1));
	}

	/// The DER of the descriptor of [`TightbeamProfile`].
	#[cfg(all(feature = "testing", any(feature = "transport-cms", feature = "transport-hpke")))]
	const TIGHTBEAM_DESCRIPTOR: &str = "304ca00b0609608648016503040208a10b0609608648016503\
		04012ea20b060960864801650304030aa30d060b2a864886f70d0109100321a40706052b8104000a\
		a50b060960864801650304012d";

	/// The DER of the descriptor of the SHA3-512 profile of the test fixtures.
	#[cfg(all(feature = "testing", any(feature = "transport-cms", feature = "transport-hpke")))]
	const SHA3_512_DESCRIPTOR: &str = "304ca00b060960864801650304020aa10b0609608648016503\
		04012ea20b060960864801650304030aa30d060b2a864886f70d0109100321a40706052b8104000a\
		a50b060960864801650304012d";

	/// The house descriptors encode as their known DER, so a peer of another
	/// release reads the same profile from them.
	#[cfg(all(feature = "testing", any(feature = "transport-cms", feature = "transport-hpke")))]
	#[test]
	fn the_house_descriptors_encode_as_their_known_der() -> Result<(), Box<dyn std::error::Error>> {
		use crate::der::Encode;
		use crate::testing::fixtures::Aes256Sha3_512Profile;
		use crate::testing::unhex;

		let house = SecurityProfileDesc::from(&TightbeamProfile).to_der()?;
		let fixture = SecurityProfileDesc::from(&Aes256Sha3_512Profile).to_der()?;
		assert_eq!((house, fixture), (unhex(TIGHTBEAM_DESCRIPTOR), unhex(SHA3_512_DESCRIPTOR)));
		Ok(())
	}

	/// The DER of the descriptor of [`PreviewPqcProfile`]: the house
	/// descriptor, with the hybrid of ML-KEM-768 and ECDH over secp256k1 as
	/// its key exchange.
	#[cfg(all(
		feature = "preview-pqc",
		feature = "testing",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	const PREVIEW_PQC_DESCRIPTOR: &str = "3051a00b0609608648016503040208a10b060960864801650304\
		012ea20b060960864801650304030aa30d060b2a864886f70d0109100321a40c060a2b0601040183\
		f84a0204a50b060960864801650304012d";

	/// The preview profile negotiates the hybrid under its own identifier,
	/// encodes as its known DER, and its 192-bit exchange meets the default
	/// floor.
	#[cfg(all(
		feature = "preview-pqc",
		feature = "testing",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	#[test]
	fn the_preview_profile_negotiates_the_hybrid() -> Result<(), Box<dyn std::error::Error>> {
		use crate::der::Encode;
		use crate::oids::KEM_SECP256K1_ML_KEM_768;
		use crate::testing::unhex;
		use crate::transport::handshake::negotiation::RunnableProfile;

		let descriptor = SecurityProfileDesc::from(&PreviewPqcProfile);
		let strength = RunnableProfile::<PreviewPqcProvider>::native().strength();

		let negotiated = (descriptor.key_exchange, strength.key_exchange);
		let expected = (Some(KEM_SECP256K1_ML_KEM_768), SecurityStrength::BITS_192);
		assert_eq!(negotiated, expected);
		assert!(PreviewPqcProvider::strength_floor().meets_floor(&strength));
		assert_eq!(descriptor.to_der()?, unhex(PREVIEW_PQC_DESCRIPTOR));
		Ok(())
	}

	/// A server that supports the preview profile alone finds no profile in an
	/// offer of the house profile alone, since the two name other exchanges.
	#[cfg(all(
		feature = "preview-pqc",
		feature = "testing",
		any(feature = "transport-cms", feature = "transport-hpke")
	))]
	#[test]
	fn a_house_offer_finds_no_profile_on_a_preview_server() {
		use crate::transport::handshake::negotiation::{NegotiationError, SecurityOffer};

		let offer = SecurityOffer::new(Vec::from([SecurityProfileDesc::from(&TightbeamProfile)]));
		let supported = [SecurityProfileDesc::from(&PreviewPqcProfile)];

		let selected = offer.select_profile(supported);
		assert!(matches!(selected, Err(NegotiationError::NoMutualProfile)));
	}

	/// Each ECC order rates as its row of NIST SP 800-57 Part 1 Rev. 5 Table 2:
	/// the first order of each row, and the last order of the row below it.
	#[test]
	fn each_ecc_order_rates_as_its_row_of_table_2() {
		let rows = [
			(160, SecurityStrength::BITS_80),
			(223, SecurityStrength::BITS_80),
			(224, SecurityStrength::BITS_112),
			(255, SecurityStrength::BITS_112),
			(256, SecurityStrength::BITS_128),
			(383, SecurityStrength::BITS_128),
			(384, SecurityStrength::BITS_192),
			(511, SecurityStrength::BITS_192),
			(512, SecurityStrength::BITS_256),
		];

		let rated = rows.map(|(order_bits, _)| (order_bits, SecurityStrength::of_ecc_order(order_bits)));
		assert_eq!(rated, rows);
	}
}
