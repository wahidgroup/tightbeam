//! The key derivation functions (KDF).
//!
//! The module derives keys through HKDF per [RFC 5869][rfc5869], with
//! SHA3-256 as the default hash. It serves as a general-purpose KDF and as the
//! KDF of ECIES constructions that require distinct encryption and MAC keys.
//!
//! # Properties
//!
//! - The default provider is HKDF ([RFC 5869][rfc5869]) with SHA3-256.
//! - Derivation is deterministic, and the `info` parameter separates domains ([RFC 5869 §3.2][rfc5869-3.2]).
//! - Key material stays in buffers that wipe on drop. The keys and outputs
//!   are `Zeroizing` and `ZeroizingArray` buffers. HKDF and X9.63 hash
//!   through the core of the digest with a buffer of their own, so the
//!   pseudorandom key, each output block, and each input that a hash buffers
//!   wipe as well. The digest core wipes its own state, as the contract of
//!   [`DigestProvider::Digest`] asks and the house SHA3 cores hold.
//! - Input validation covers the shared secret, which [`EcdhSecret`] fixes at
//!   the field width of its curve, and the output length, which each provider
//!   bounds.
//!
//! # Providers
//!
//! - HKDF providers honor the optional `salt` parameter per [RFC 5869 §2.2][rfc5869-2.2].
//! - ANSI X9.63 providers ignore `salt`. Their derivation depends on the shared
//!   secret Z and the `info` (SharedInfo) context bytes only
//!   ([SECG SEC 1 v2.0 §3.6][sec1-3.6]).
//!
//! # ECIES
//!
//! - ECIES profiles such as [SECG SEC 1 v2.0 §5.1][sec1-5.1],
//!   [IEEE Std 1363a-2004][ieee1363a], and [ISO/IEC 18033-2:2006][iso18033]
//!   mandate separate symmetric encryption and MAC keys.
//!   [`DualKeyKdf::derive_dual_keys`] enforces that key separation with one
//!   expansion split into two disjoint keys
//!   ([SECG SEC 1 v2.0 §5.1.3][sec1-5.1.3]).
//! - Those standards derive with a counter-mode hash KDF. [`X963Sha3_256`] is
//!   the ANSI X9.63 construction ([SECG SEC 1 v2.0 §3.6][sec1-3.6]) over
//!   SHA3-256.
//! - The public-key encryption of this crate is HPKE ([RFC 9180][rfc9180]), in
//!   `crypto::hpke`. It keys one AEAD, and it derives through the labeled
//!   schedule of that RFC.
//!
//! # Sources
//!
//! - [RFC 5869][rfc5869]: HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
//! - [RFC 9180][rfc9180]: Hybrid Public Key Encryption.
//! - [NIST SP 800-56A Rev. 3 §5.8][sp800-56a]: Key-Derivation Methods for Key-Agreement Schemes.
//! - [NIST SP 800-56C Rev. 2 §2][sp800-56c-2]: the hybrid shared secret
//!   `Z′ = Z || T`, the input of the handshake secret.
//! - [NIST SP 800-56C Rev. 2 §5][sp800-56c]: Two-Step Key Derivation, which
//!   HKDF instantiates with HMAC in both steps (§5.1).
//! - [SECG SEC 1 v2.0 §5.1][sec1-5.1]: Elliptic Curve Integrated Encryption Scheme (ECIES).
//! - [IEEE Std 1363a-2004][ieee1363a]: Public-Key Cryptography, Amendment 1 (Additional Techniques).
//! - [ISO/IEC 18033-2:2006][iso18033]: Encryption algorithms, Part 2: Asymmetric ciphers.
//!
//! [`DigestProvider::Digest`]: crate::crypto::profiles::DigestProvider::Digest
//! [rfc5869]: https://datatracker.ietf.org/doc/html/rfc5869
//! [rfc9180]: https://datatracker.ietf.org/doc/html/rfc9180
//! [rfc5869-2.2]: https://datatracker.ietf.org/doc/html/rfc5869#section-2.2
//! [rfc5869-3.2]: https://datatracker.ietf.org/doc/html/rfc5869#section-3.2
//! [sp800-56a]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf#page=64
//! [sp800-56c-2]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf#page=10
//! [sp800-56c]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf#page=25
//! [sec1-3.6]: https://www.secg.org/sec1-v2.pdf#page=37
//! [sec1-5.1]: https://www.secg.org/sec1-v2.pdf#page=57
//! [sec1-5.1.3]: https://www.secg.org/sec1-v2.pdf#page=59
//! [ieee1363a]: https://standards.ieee.org/standard/1363a-2004.html
//! [iso18033]: https://www.iso.org/standard/37971.html

mod zeroizing;

pub use crate::crypto::hkdf::Hkdf;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) use zeroizing::ZeroizingHmac;
pub(crate) use zeroizing::{ZeroizingHash, ZeroizingHkdf};

use crate::constants::{MAX_HKDF_OUTPUT_SIZE, MIN_KEY_SIZE};
use crate::crypto::hash::{Digest, Sha3_256};
use crate::crypto::hkdf::InvalidLength;
use crate::crypto::secret::{Secret, SecretSlice};
use crate::der::asn1::ObjectIdentifier;
use crate::der::oid::AssociatedOid;
use crate::error::ReceivedExpectedError;
use crate::oids::HKDF_SHA3_256;
use crate::zeroize::Zeroizing;
use crate::Errorizable;
use crate::{ZeroizingArray, ZeroizingBytes};
use elliptic_curve::{Curve, FieldBytes};

#[cfg(any(feature = "ecdh", feature = "hpke"))]
use elliptic_curve::ecdh::{diffie_hellman, SharedSecret};
#[cfg(any(feature = "ecdh", feature = "hpke"))]
use elliptic_curve::{CurveArithmetic, PublicKey, SecretKey};

/// The result of a KDF operation.
pub type Result<T> = ::core::result::Result<T, KdfError>;

/// A key derivation function that a provider type implements.
///
/// A consumer plugs in a RustCrypto KDF or a custom KDF through this trait.
/// The contract of an implementation is to wipe the pseudorandom key, each
/// output block it chains, and each input that a hash buffers, once the
/// derivation ends (NIST SP 800-56C Rev. 2 §5.1). The house providers hold
/// it through hashes whose buffers wipe on drop.
pub trait KdfFunction {
	/// Derives a key whose size is known only at run time.
	///
	/// A negotiated security profile sets the key size, so a const generic
	/// cannot carry it. Each provider uses its own digest algorithm.
	///
	/// - `ikm`: the input key material.
	/// - `info`: the context string for domain separation.
	/// - `salt`: an optional salt, 16 bytes or more when present.
	/// - `key_size`: the output key size in bytes.
	///
	/// # Errors
	///
	/// - [`KdfError::DerivationFailed`] -- `key_size` is outside the valid range.
	fn derive_dynamic_key(ikm: &[u8], info: &[u8], salt: Option<&[u8]>, key_size: usize) -> Result<ZeroizingBytes>;
}

/// The dual-key derivation through any [`KdfFunction`].
///
/// The blanket implementation is the only one, so a KDF identifier names one
/// dual-key output whichever type implements it.
pub trait DualKeyKdf: KdfFunction {
	/// Derives an ECIES encryption key and MAC key of `N` bytes each.
	///
	/// ECIES standards such as [SECG SEC 1 v2.0 §5.1][sec1-5.1],
	/// [IEEE Std 1363a-2004][ieee1363a], and [ISO/IEC 18033-2:2006][iso18033]
	/// require distinct symmetric keys for encryption and for message
	/// authentication, so each primitive holds a key of its own. One
	/// construction serves every KDF:
	///
	/// 1. Expand `2 * N` bytes once through [`KdfFunction::derive_dynamic_key`].
	/// 2. Split the output into two disjoint keys ([SECG SEC 1 v2.0 §5.1.3][sec1-5.1.3]).
	///
	/// # Errors
	///
	/// - [`KdfError::DerivationFailed`] -- `N` is below [`MIN_KEY_SIZE`], or
	///   the KDF refuses `2 * N` bytes or returns another length.
	///
	/// # Sources
	///
	/// - [RFC 5869 §3.2][rfc5869-3.2]: `info` for context separation.
	/// - [NIST SP 800-56C Rev. 2 §5][sp800-56c]: extraction-then-expansion and context binding.
	/// - [SECG SEC 1 v2.0 §5.1.3][sec1-5.1.3]: ECIES encryption and MAC key separation.
	///
	/// [rfc5869-3.2]: https://datatracker.ietf.org/doc/html/rfc5869#section-3.2
	/// [sp800-56c]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf#page=25
	/// [sec1-5.1]: https://www.secg.org/sec1-v2.pdf#page=57
	/// [sec1-5.1.3]: https://www.secg.org/sec1-v2.pdf#page=59
	/// [ieee1363a]: https://standards.ieee.org/standard/1363a-2004.html
	/// [iso18033]: https://www.iso.org/standard/37971.html
	fn derive_dual_keys<const N: usize>(
		ikm: &[u8],
		info: &[u8],
		salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)>;
}

impl<K: KdfFunction> DualKeyKdf for K {
	fn derive_dual_keys<const N: usize>(
		ikm: &[u8],
		info: &[u8],
		salt: Option<&[u8]>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)> {
		assert_min_key_size(N)?;

		let combined_len = N.checked_mul(2).ok_or(KdfError::DerivationFailed(InvalidLength))?;
		let combined = K::derive_dynamic_key(ikm, info, salt, combined_len)?;
		let (enc_bytes, mac_bytes) = combined
			.split_at_checked(N)
			.filter(|(_, mac_bytes)| mac_bytes.len() == N)
			.ok_or(KdfError::DerivationFailed(InvalidLength))?;

		let mut k_enc = Zeroizing::new([0u8; N]);
		let mut k_mac = Zeroizing::new([0u8; N]);
		k_enc.copy_from_slice(enc_bytes);
		k_mac.copy_from_slice(mac_bytes);

		Ok((k_enc, k_mac))
	}
}

/// The default KDF provider, which is HKDF over SHA3-256.
pub struct HkdfSha3_256;

/// HKDF with SHA3-256 has an OID of its own, `id-alg-hkdf-with-sha3-256`
/// ([RFC 9688 §5.1][rfc9688-5.1]), and a security profile negotiates the KDF
/// under it.
///
/// [rfc9688-5.1]: https://datatracker.ietf.org/doc/html/rfc9688#section-5.1
impl AssociatedOid for HkdfSha3_256 {
	const OID: ObjectIdentifier = HKDF_SHA3_256;
}

/// Rejects a key size below [`MIN_KEY_SIZE`], which is too weak for
/// cryptographic use.
///
/// The X9.63 provider and the dual-key derivation share this check, so the
/// two apply one validation.
#[inline]
fn assert_min_key_size(key_size: usize) -> Result<()> {
	if key_size < MIN_KEY_SIZE {
		return Err(KdfError::DerivationFailed(InvalidLength));
	}

	Ok(())
}

/// Rejects a key size outside `[MIN_KEY_SIZE, MAX_HKDF_OUTPUT_SIZE]`.
///
/// This is the HKDF counterpart of [`assert_min_key_size`]. The crate policy
/// [`MAX_HKDF_OUTPUT_SIZE`] also caps HKDF output.
#[inline]
fn assert_hkdf_key_size(key_size: usize) -> Result<()> {
	if !(MIN_KEY_SIZE..=MAX_HKDF_OUTPUT_SIZE).contains(&key_size) {
		return Err(KdfError::DerivationFailed(InvalidLength));
	}

	Ok(())
}

impl KdfFunction for HkdfSha3_256 {
	fn derive_dynamic_key(ikm: &[u8], info: &[u8], salt: Option<&[u8]>, key_size: usize) -> Result<ZeroizingBytes> {
		assert_hkdf_key_size(key_size)?;

		let hkdf = ZeroizingHkdf::<Sha3_256>::new(salt.unwrap_or_default(), ikm);
		let mut okm = Zeroizing::new(vec![0u8; key_size]);
		hkdf.expand(info, &mut okm).map_err(KdfError::DerivationFailed)?;

		Ok(okm)
	}
}

/// The ANSI X9.63 concatenation KDF over SHA3-256.
pub struct X963Sha3_256;

impl KdfFunction for X963Sha3_256 {
	fn derive_dynamic_key(ikm: &[u8], info: &[u8], _salt: Option<&[u8]>, key_size: usize) -> Result<ZeroizingBytes> {
		assert_min_key_size(key_size)?;

		// The output wipes from its first derived byte, so a refused expansion
		// wipes its partial output when it drops.
		let mut out = Zeroizing::new(vec![0u8; key_size]);
		Self::expand(&mut out, ikm, info)?;
		Ok(out)
	}
}

impl X963Sha3_256 {
	/// ANSI X9.63 concatenation: `K(i) = Hash(Z || Counter_i || SharedInfo)`.
	///
	/// `Counter_i` starts at 1. A counter that would overflow `u32` fails the
	/// derivation, so the counter never wraps.
	fn expand(out: &mut [u8], ikm: &[u8], info: &[u8]) -> Result<()> {
		let mut counter: u32 = 1;
		let mut windows = out.chunks_mut(<Sha3_256 as Digest>::output_size()).peekable();
		while let Some(window) = windows.next() {
			let hasher = ZeroizingHash::<Sha3_256>::new().chain_update(ikm);
			let hasher = hasher.chain_update(&counter.to_be_bytes()).chain_update(info);

			let block = hasher.finalize();
			for (octet, derived) in window.iter_mut().zip(block.as_slice()) {
				*octet = *derived;
			}

			if windows.peek().is_some() {
				counter = counter.checked_add(1).ok_or(KdfError::DerivationFailed(InvalidLength))?;
			}
		}

		Ok(())
	}
}

/// An error from a KDF operation.
#[derive(Errorizable, Debug, Clone)]
pub enum KdfError {
	/// A key derivation failure: the output length is out of range, or the
	/// HKDF expansion fails.
	#[error("Key derivation failed: {0}")]
	DerivationFailed(InvalidLength),

	/// The shared secret is not as wide as the field of its curve. The variant
	/// holds the received and the expected length.
	#[error("Invalid shared secret length: {0}")]
	InvalidSharedSecretLength(ReceivedExpectedError<usize, usize>),
}

/// An ECDH shared secret on the curve `C`: the x-coordinate of the product of
/// a scalar and a peer point (SEC 1 v2.0 §3.3.1).
///
/// It is as wide as the field of `C`, the `Ndh` of RFC 9180 §4.1: 32 bytes on
/// secp256k1 and P-256, 48 on P-384, and 66 on P-521. The curve is part of the
/// type, so a derivation that takes one relies on the type for its width. It
/// wipes on drop like every [`Secret`].
///
/// # Examples
///
/// ```
/// use p384::{NistP384, SecretKey};
/// use tightbeam::crypto::kdf::EcdhSecret;
/// use tightbeam::random::OsRng;
///
/// let local = SecretKey::random(&mut OsRng);
/// let peer = SecretKey::random(&mut OsRng).public_key();
///
/// let shared = EcdhSecret::<NistP384>::agree(&local, &peer);
/// assert_eq!(shared.with(|x_coordinate| x_coordinate.len()), 48);
/// ```
#[derive(Debug)]
pub struct EcdhSecret<C: Curve>(Secret<FieldBytes<C>>);

impl<C: Curve> TryFrom<SecretSlice<u8>> for EcdhSecret<C> {
	type Error = KdfError;

	/// # Errors
	///
	/// - [`KdfError::InvalidSharedSecretLength`] -- the secret is not as wide as the field of `C`.
	fn try_from(secret: SecretSlice<u8>) -> Result<Self> {
		secret.with(|bytes| Self::sized(bytes))
	}
}

/// Moves a curve shared secret into the type the key schedule takes, at the
/// width of the field of `C`. The curve secret wipes when it drops.
#[cfg(any(feature = "ecdh", feature = "hpke"))]
impl<C: Curve> From<SharedSecret<C>> for EcdhSecret<C> {
	fn from(shared: SharedSecret<C>) -> Self {
		Self::copy_of(shared.raw_secret_bytes())
	}
}

impl<C: Curve> EcdhSecret<C> {
	/// Lends the secret to `f` for the length of the call, so a derivation
	/// reads it with no owned copy.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::k256::Secp256k1;
	/// use tightbeam::crypto::kdf::EcdhSecret;
	/// use tightbeam::crypto::secret::SecretSlice;
	///
	/// let shared = EcdhSecret::<Secp256k1>::try_from(SecretSlice::from(vec![0x11; 32]))?;
	/// assert!(shared.with(|x_coordinate| x_coordinate.iter().all(|&octet| octet == 0x11)));
	/// # Ok::<(), tightbeam::crypto::kdf::KdfError>(())
	/// ```
	pub fn with<R>(&self, f: impl FnOnce(&FieldBytes<C>) -> R) -> R {
		self.0.with(f)
	}

	/// Returns a secret that holds a copy of `bytes`.
	///
	/// The bytes land in the wiping buffer directly, so no plain array of the
	/// shared secret exists on the way (CWE-226). Every conversion from a curve
	/// [`SharedSecret`] copies here, and the output of a provider copies in
	/// [`Self::sized`].
	#[cfg(any(test, feature = "ecdh", feature = "hpke"))]
	fn copy_of(bytes: &FieldBytes<C>) -> Self {
		let mut sized = Zeroizing::new(FieldBytes::<C>::default());
		sized.copy_from_slice(bytes);
		Self(Secret::from(sized))
	}

	/// Checks the length of `bytes` against the field of `C`, then copies them
	/// into the wiping buffer of the secret (CWE-226).
	///
	/// # Errors
	///
	/// - [`KdfError::InvalidSharedSecretLength`] -- `bytes` is not as wide as the field of `C`.
	fn sized(bytes: &[u8]) -> Result<Self> {
		let mut sized = Zeroizing::new(FieldBytes::<C>::default());
		if bytes.len() != sized.len() {
			let width = ReceivedExpectedError { received: bytes.len(), expected: sized.len() };
			return Err(KdfError::InvalidSharedSecretLength(width));
		}

		sized.copy_from_slice(bytes);
		Ok(Self(Secret::from(sized)))
	}

	/// Returns a second owner of this secret, for a holder that derives from
	/// it more than once.
	#[cfg(test)]
	pub(crate) fn duplicate(&self) -> Self {
		self.with(Self::copy_of)
	}

	/// Runs ECDH between `secret` and the peer's point `peer`.
	///
	/// HPKE and the handshake agreement of a held key both multiply here. Two
	/// other holders of a scalar multiply on their own: an `EphemeralSecret`,
	/// which keeps its scalar private, and a `SigningKeyProvider`, whose key
	/// may live outside the process. Each of them converts its output into
	/// this type.
	///
	/// # Examples
	///
	/// ```
	/// use p521::{NistP521, SecretKey};
	/// use tightbeam::crypto::kdf::EcdhSecret;
	/// use tightbeam::random::OsRng;
	///
	/// let alice = SecretKey::random(&mut OsRng);
	/// let bob = SecretKey::random(&mut OsRng);
	///
	/// let by_alice = EcdhSecret::<NistP521>::agree(&alice, &bob.public_key());
	/// let by_bob = EcdhSecret::<NistP521>::agree(&bob, &alice.public_key());
	/// assert_eq!(by_alice.with(|x| x.to_vec()), by_bob.with(|x| x.to_vec()));
	/// ```
	#[cfg(any(feature = "ecdh", feature = "hpke"))]
	pub fn agree(secret: &SecretKey<C>, peer: &PublicKey<C>) -> Self
	where
		C: CurveArithmetic,
	{
		let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
		Self::from(shared)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::k256::Secp256k1;
	use p521::NistP521;

	#[track_caller]
	fn assert_key_length(key: &[u8], expected_len: usize) {
		assert_eq!(key.len(), expected_len, "Key length mismatch");
	}

	#[track_caller]
	fn assert_keys_equal(key1: &[u8], key2: &[u8]) {
		assert_eq!(key1[..], key2[..], "Keys should be equal");
	}

	#[track_caller]
	fn assert_keys_different(key1: &[u8], key2: &[u8]) {
		assert_ne!(key1[..], key2[..], "Keys should be different");
	}

	macro_rules! assert_key_pair_lengths {
		($enc:expr, $mac:expr, $size:expr) => {
			assert_eq!($enc.len(), $size, "Encryption key length mismatch");
			assert_eq!($mac.len(), $size, "MAC key length mismatch");
		};
	}

	macro_rules! assert_keys_different {
		($key1:expr, $key2:expr) => {
			assert_ne!($key1[..], $key2[..], "Keys should be different");
		};
	}

	macro_rules! assert_key_length {
		($key:expr, $size:expr) => {
			assert_eq!($key.len(), $size, "Key length mismatch");
		};
	}

	const SHARED_SECRET: &[u8] = b"shared_secret_32_bytes__________";
	const INFO_V1: &[u8] = b"tightbeam-ecies-v1";
	const INFO_V2: &[u8] = b"protocol-v2";
	const SALT: &[u8] = b"random_salt_value";

	// `EcdhSecret` refuses a shared secret of another width than the field of
	// its curve, so every derivation runs on exactly that width: 32 bytes on
	// secp256k1, and 66 on P-521.
	#[test]
	fn a_shared_secret_of_the_wrong_length_is_refused() {
		let short = EcdhSecret::<Secp256k1>::try_from(SecretSlice::from(b"short".to_vec()));
		let long = EcdhSecret::<Secp256k1>::try_from(SecretSlice::from(b"shared_secret_that_is_too_long____".to_vec()));
		let narrow = EcdhSecret::<NistP521>::try_from(SecretSlice::from(vec![0x11; 32]));
		let short_width = ReceivedExpectedError { received: 5, expected: 32 };
		let long_width = ReceivedExpectedError { received: 34, expected: 32 };
		let narrow_width = ReceivedExpectedError { received: 32, expected: 66 };
		assert!(matches!(short, Err(KdfError::InvalidSharedSecretLength(width)) if width == short_width));
		assert!(matches!(long, Err(KdfError::InvalidSharedSecretLength(width)) if width == long_width));
		assert!(matches!(narrow, Err(KdfError::InvalidSharedSecretLength(width)) if width == narrow_width));
	}

	// General-purpose HKDF derives 16, 32, and 64-byte keys. The same inputs
	// derive the same key, and a different IKM derives a different key.
	#[test]
	fn test_hkdf_sha3_256_basic() -> crate::error::Result<()> {
		let ikm = b"input_key_material";
		let info = b"test_info";

		let key_16 = HkdfSha3_256::derive_dynamic_key(ikm, info, None, 16)?;
		let key_32 = HkdfSha3_256::derive_dynamic_key(ikm, info, None, 32)?;
		let key_64 = HkdfSha3_256::derive_dynamic_key(ikm, info, None, 64)?;

		let key_32_again = HkdfSha3_256::derive_dynamic_key(ikm, info, None, 32)?;
		let key_different = HkdfSha3_256::derive_dynamic_key(b"different_ikm", info, None, 32)?;

		assert_key_length!(key_16, 16);
		assert_key_length!(key_32, 32);
		assert_key_length!(key_64, 64);
		assert_eq!(key_32[..], key_32_again[..]);
		assert_keys_different!(key_32, key_different);

		Ok(())
	}

	// A dual-key size of 64 bytes expands to 128 bytes, which equals
	// `MAX_HKDF_OUTPUT_SIZE`, so it derives. A size of 65 bytes expands to 130
	// bytes, which is past the cap, so it fails with `DerivationFailed`.
	#[test]
	fn test_hkdf_dual_keys_bounds_checking() -> crate::error::Result<()> {
		let max_size_result = HkdfSha3_256::derive_dual_keys::<64>(SHARED_SECRET, INFO_V1, None);
		let oversized_result = HkdfSha3_256::derive_dual_keys::<65>(SHARED_SECRET, INFO_V1, None);
		assert!(max_size_result.is_ok());

		let (k_enc, k_mac) = max_size_result?;
		assert_key_pair_lengths!(k_enc, k_mac, 64);

		assert!(oversized_result.is_err());
		assert!(matches!(oversized_result, Err(KdfError::DerivationFailed(_))));

		Ok(())
	}

	// The ANSI X9.63 provider over SHA3-256 is deterministic and binds the
	// info.
	#[test]
	fn test_x963_kdf_basic() -> crate::error::Result<()> {
		let key1 = X963Sha3_256::derive_dynamic_key(SHARED_SECRET, INFO_V1, None, 32)?;
		let key1_again = X963Sha3_256::derive_dynamic_key(SHARED_SECRET, INFO_V1, None, 32)?;
		let key_diff_info = X963Sha3_256::derive_dynamic_key(SHARED_SECRET, INFO_V2, None, 32)?;
		// X9.63 ignores the salt, so a salted key equals the unsalted key.
		let key_with_salt = X963Sha3_256::derive_dynamic_key(SHARED_SECRET, INFO_V1, Some(SALT), 32)?;
		assert_key_length(&key1, 32);
		assert_keys_equal(&key1, &key1_again);
		assert_keys_different(&key1, &key_diff_info);
		assert_keys_equal(&key1, &key_with_salt);
		Ok(())
	}

	#[test]
	fn test_x963_dual_key_size_variations() -> crate::error::Result<()> {
		let keys_16 = X963Sha3_256::derive_dual_keys::<16>(SHARED_SECRET, INFO_V1, None)?;
		let keys_32 = X963Sha3_256::derive_dual_keys::<32>(SHARED_SECRET, INFO_V1, None)?;

		let (k_enc_16, k_mac_16) = keys_16;
		let (k_enc_32, k_mac_32) = keys_32;
		assert_key_pair_lengths!(k_enc_16, k_mac_16, 16);
		assert_key_pair_lengths!(k_enc_32, k_mac_32, 32);
		assert_keys_different!(k_enc_32, k_mac_32);
		Ok(())
	}

	// Both providers reject an output below `MIN_KEY_SIZE`, and the HKDF
	// provider also rejects an output past `MAX_HKDF_OUTPUT_SIZE`.
	#[test]
	fn test_derive_dynamic_key_bounds() {
		let hkdf_below_min = HkdfSha3_256::derive_dynamic_key(b"ikm", b"info", None, 8);
		let hkdf_above_max = HkdfSha3_256::derive_dynamic_key(b"ikm", b"info", None, 129);
		let x963_below_min = X963Sha3_256::derive_dynamic_key(b"ikm", b"info", None, 8);
		assert!(matches!(hkdf_below_min, Err(KdfError::DerivationFailed(_))));
		assert!(matches!(hkdf_above_max, Err(KdfError::DerivationFailed(_))));
		assert!(matches!(x963_below_min, Err(KdfError::DerivationFailed(_))));
	}

	// A SharedInfo longer than 256 bytes must derive a key pair without a
	// panic, so no fixed 256-byte buffer bounds the info.
	#[test]
	fn test_x963_dual_keys_large_shared_info() -> crate::error::Result<()> {
		let large_info = vec![0xABu8; 300];
		let (k_enc, k_mac) = X963Sha3_256::derive_dual_keys::<32>(SHARED_SECRET, &large_info, None)?;

		assert_key_pair_lengths!(k_enc, k_mac, 32);
		assert_keys_different!(k_enc, k_mac);
		Ok(())
	}

	// The HKDF dual-key output is the interoperable ECIES key schedule, which
	// is the two halves of one RFC 5869 expansion.
	#[test]
	fn an_hkdf_dual_key_pair_is_one_expansion_split_in_half() -> crate::error::Result<()> {
		let mut expected = [0u8; 64];
		Hkdf::<Sha3_256>::new(Some(SALT), b"ikm")
			.expand(INFO_V1, &mut expected)
			.map_err(KdfError::DerivationFailed)?;

		let (k_enc, k_mac) = HkdfSha3_256::derive_dual_keys::<32>(b"ikm", INFO_V1, Some(SALT))?;
		assert_eq!(k_enc[..], expected[..32]);
		assert_eq!(k_mac[..], expected[32..]);
		Ok(())
	}

	// An unsalted derivation is the RFC 5869 derivation under a salt of
	// zeros as long as the hash, which `hkdf` 0.12 takes for an absent salt.
	#[test]
	fn an_unsalted_hkdf_key_is_the_expansion_under_a_salt_of_zeros() -> crate::error::Result<()> {
		let mut expected = [0u8; 32];
		let reference = Hkdf::<Sha3_256>::new(None, b"ikm").expand(INFO_V1, &mut expected);
		reference.map_err(KdfError::DerivationFailed)?;

		let key = HkdfSha3_256::derive_dynamic_key(b"ikm", INFO_V1, None, 32)?;
		assert_eq!(key[..], expected[..]);
		Ok(())
	}

	// Each X9.63 block is the hash of the secret, the counter, and the
	// SharedInfo, in that order.
	#[test]
	fn an_x963_block_is_the_hash_of_the_secret_the_counter_and_the_info() -> crate::error::Result<()> {
		let expected = Sha3_256::digest([SHARED_SECRET, &1u32.to_be_bytes(), INFO_V1].concat());

		let key = X963Sha3_256::derive_dynamic_key(SHARED_SECRET, INFO_V1, None, 32)?;
		assert_eq!(key[..], expected[..]);
		Ok(())
	}

	// X9.63 dual keys split one expansion the same way.
	#[test]
	fn an_x963_dual_key_pair_is_one_expansion_split_in_half() -> crate::error::Result<()> {
		let expected = X963Sha3_256::derive_dynamic_key(b"ikm", INFO_V1, None, 64)?;
		let (k_enc, k_mac) = X963Sha3_256::derive_dual_keys::<32>(b"ikm", INFO_V1, None)?;
		assert_eq!(k_enc[..], expected[..32]);
		assert_eq!(k_mac[..], expected[32..]);
		Ok(())
	}

	#[test]
	fn a_dual_key_below_the_minimum_size_is_refused() {
		let result = X963Sha3_256::derive_dual_keys::<8>(b"ikm", INFO_V1, None);
		assert!(matches!(result, Err(KdfError::DerivationFailed(_))));
	}
}
