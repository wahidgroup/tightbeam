//! The key derivation functions (KDF).
//!
//! The module derives keys through HKDF ([RFC 5869][rfc5869]) for general use
//! and for the ECIES constructions that require distinct encryption and MAC
//! keys.
//!
//! # Properties
//!
//! - The default provider is HKDF ([RFC 5869][rfc5869]) with SHA3-256.
//! - Derivation is deterministic, and the `info` parameter separates domains ([RFC 5869 §3.2][rfc5869-3.2]).
//! - Key material stays in buffers that wipe on drop: the keys and outputs
//!   are `Zeroizing` and `ZeroizingArray`. HKDF and X9.63 drive the digest
//!   core with a buffer of their own, so the pseudorandom key, each output
//!   block, and each input that a hash buffers wipe too. The core wipes its
//!   own state, as [`DigestProvider::Digest`] asks and the house SHA3 cores do.
//! - Input validation covers the shared secret, which [`EcdhSecret`] fixes at
//!   the field width of its curve, and the output length, which each provider
//!   bounds.
//!
//! # Providers
//!
//! - HKDF providers honor the optional `salt` parameter per [RFC 5869 §2.2][rfc5869-2.2].
//! - ANSI X9.63 providers ignore `salt` and derive from the shared secret Z
//!   and the `info` (SharedInfo) alone ([SECG SEC 1 v2.0 §3.6][sec1-3.6]).
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

use crate::constants::{MAX_HKDF_OUTPUT_SIZE, MIN_KEY_SIZE, MIN_SALT_ENTROPY_BYTES};
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

/// The salt of one key derivation, which the KDF mixes into its extract step.
///
/// Its one constructor is `TryFrom<&[u8]>`, which refuses a salt shorter than
/// [`MIN_SALT_ENTROPY_BYTES`], so every [`KdfFunction`] receives a salt at
/// that floor. The salt and the `info` label arrive as distinct types, so a
/// call that exchanges the two fails to compile.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::kdf::{KdfError, KdfSalt};
///
/// // A salt of 32 octets meets the floor of 16.
/// let salt = KdfSalt::try_from([0x99u8; 32].as_slice())?;
/// assert_eq!(salt.as_bytes().len(), 32);
///
/// let short = KdfSalt::try_from(b"ab".as_slice());
/// assert!(matches!(short, Err(KdfError::SaltTooShort { actual: 2, minimum: 16 })));
/// # Ok::<(), KdfError>(())
/// ```
///
/// # Sources
///
/// - RFC 5869 § 2.2, the extract step and its salt:
///   <https://datatracker.ietf.org/doc/html/rfc5869#section-2.2>
#[derive(Clone, Copy, Debug)]
pub struct KdfSalt<'a>(&'a [u8]);

impl<'a> KdfSalt<'a> {
	/// The salt bytes, for the derivation that consumes them.
	#[must_use]
	pub fn as_bytes(&self) -> &'a [u8] {
		self.0
	}
}

impl<'a> TryFrom<&'a [u8]> for KdfSalt<'a> {
	type Error = KdfError;

	/// Admits `salt` as the salt of one derivation.
	///
	/// # Errors
	///
	/// - [`KdfError::SaltTooShort`] -- `salt` is shorter than [`MIN_SALT_ENTROPY_BYTES`].
	fn try_from(salt: &'a [u8]) -> Result<Self> {
		let actual = salt.len();
		if actual < MIN_SALT_ENTROPY_BYTES {
			return Err(KdfError::SaltTooShort { actual, minimum: MIN_SALT_ENTROPY_BYTES });
		}

		Ok(Self(salt))
	}
}

/// A key derivation function that a provider type implements.
///
/// A consumer plugs in a RustCrypto or a custom KDF through this trait. The
/// contract of an implementation is to wipe the pseudorandom key, each output
/// block it chains, and each input that a hash buffers once the derivation
/// ends (NIST SP 800-56C Rev. 2 §5.1). The house providers hash through
/// buffers that wipe on drop.
pub trait KdfFunction {
	/// Derives a key whose size is known only at run time.
	///
	/// A negotiated security profile sets the key size, so a const generic
	/// cannot carry it. Each provider uses its own digest algorithm.
	///
	/// - `ikm`: the input key material.
	/// - `info`: the context string for domain separation.
	/// - `salt`: an optional salt, which [`KdfSalt`] holds at [`MIN_SALT_ENTROPY_BYTES`] bytes or more.
	/// - `key_size`: the output key size in bytes.
	///
	/// # Errors
	///
	/// - [`KdfError::DerivationFailed`] -- `key_size` is outside the valid range.
	fn derive_dynamic_key(
		ikm: &[u8],
		info: &[u8],
		salt: Option<KdfSalt<'_>>,
		key_size: usize,
	) -> Result<ZeroizingBytes>;
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
	/// authentication. One construction serves every KDF:
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
		salt: Option<KdfSalt<'_>>,
	) -> Result<(ZeroizingArray<N>, ZeroizingArray<N>)>;
}

impl<K: KdfFunction> DualKeyKdf for K {
	fn derive_dual_keys<const N: usize>(
		ikm: &[u8],
		info: &[u8],
		salt: Option<KdfSalt<'_>>,
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
/// The X9.63 provider and the dual-key derivation share this check.
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
	fn derive_dynamic_key(
		ikm: &[u8],
		info: &[u8],
		salt: Option<KdfSalt<'_>>,
		key_size: usize,
	) -> Result<ZeroizingBytes> {
		assert_hkdf_key_size(key_size)?;

		let salt = salt.map(|salt| salt.as_bytes()).unwrap_or_default();
		let hkdf = ZeroizingHkdf::<Sha3_256>::new(salt, ikm);
		let mut okm = Zeroizing::new(vec![0u8; key_size]);
		hkdf.expand(info, &mut okm).map_err(KdfError::DerivationFailed)?;

		Ok(okm)
	}
}

/// The ANSI X9.63 concatenation KDF over SHA3-256.
///
/// It derives from the shared secret and the `info` alone, so its output is
/// the same under any salt ([SECG SEC 1 v2.0 §3.6][sec1-3.6]).
///
/// [sec1-3.6]: https://www.secg.org/sec1-v2.pdf#page=37
pub struct X963Sha3_256;

impl KdfFunction for X963Sha3_256 {
	fn derive_dynamic_key(
		ikm: &[u8],
		info: &[u8],
		_salt: Option<KdfSalt<'_>>,
		key_size: usize,
	) -> Result<ZeroizingBytes> {
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

	/// A salt is shorter than the floor of [`KdfSalt`].
	#[error("KDF salt too short: {actual} bytes, below the minimum of {minimum}")]
	SaltTooShort {
		/// The length of the salt in bytes.
		actual: usize,
		/// The floor in bytes, [`MIN_SALT_ENTROPY_BYTES`].
		minimum: usize,
	},
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
	/// shared secret exists on the way (CWE-226). Every HPKE conversion from a
	/// curve [`SharedSecret`] copies here, and the output of a provider copies
	/// in [`Self::sized`].
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

	/// Runs ECDH between `secret` and the peer's point `peer`.
	///
	/// HPKE multiplies here. A `SigningKeyProvider`, whose key may live outside
	/// the process, multiplies on its own and converts its output into this
	/// type.
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
	use p521::NistP521;

	use super::*;
	use crate::crypto::k256::Secp256k1;

	const SHARED_SECRET: &[u8] = b"shared_secret_32_bytes__________";
	const INFO_V1: &[u8] = b"tightbeam-ecies-v1";
	const INFO_V2: &[u8] = b"protocol-v2";
	const SALT: &[u8] = b"random_salt_value";

	/// A SharedInfo longer than 256 octets.
	const LARGE_INFO: [u8; 300] = [0xAB; 300];

	/// [`SALT`] as the salt of one derivation.
	fn salt() -> KdfSalt<'static> {
		KdfSalt::try_from(SALT).expect("the test salt meets the floor")
	}

	/// The unsalted HKDF key of `length` octets from `ikm` under [`INFO_V1`].
	fn hkdf_key(ikm: &[u8], length: usize) -> ZeroizingBytes {
		let key = HkdfSha3_256::derive_dynamic_key(ikm, INFO_V1, None, length);
		key.expect("the test length lies within the HKDF bounds")
	}

	/// The 32-octet X9.63 key of [`SHARED_SECRET`] under `info` and `salt`.
	fn x963_key(info: &[u8], salt: Option<KdfSalt<'_>>) -> ZeroizingBytes {
		let key = X963Sha3_256::derive_dynamic_key(SHARED_SECRET, info, salt, 32);
		key.expect("32 octets lies within the X9.63 bounds")
	}

	/// The two halves of the X9.63 dual-key pair of `N` octets each, from
	/// [`SHARED_SECRET`] under `info`, joined in order.
	fn x963_pair<const N: usize>(info: &[u8]) -> Vec<u8> {
		let pair = X963Sha3_256::derive_dual_keys::<N>(SHARED_SECRET, info, None);
		let (k_enc, k_mac) = pair.expect("the test size lies within the X9.63 bounds");
		[k_enc.as_slice(), k_mac.as_slice()].concat()
	}

	/// The two halves of the HKDF dual-key pair of `N` octets each, from `ikm`
	/// under [`INFO_V1`] and `salt`, joined in order.
	fn hkdf_pair<const N: usize>(ikm: &[u8], salt: Option<KdfSalt<'_>>) -> Vec<u8> {
		let pair = HkdfSha3_256::derive_dual_keys::<N>(ikm, INFO_V1, salt);
		let (k_enc, k_mac) = pair.expect("the test size lies within the HKDF bounds");
		[k_enc.as_slice(), k_mac.as_slice()].concat()
	}

	/// The first `N` octets of the RFC 5869 expansion of `ikm` under
	/// [`INFO_V1`] and `salt`, read from `hkdf` directly.
	fn hkdf_expansion<const N: usize>(salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8> {
		let mut expansion = [0u8; N];
		let expanded = Hkdf::<Sha3_256>::new(salt, ikm).expand(INFO_V1, &mut expansion);
		expanded.expect("the test length lies within 255 blocks");
		expansion.to_vec()
	}

	/// The X9.63 block of `counter` over [`SHARED_SECRET`] and `info`, built
	/// from SHA3-256 as SEC 1 v2.0 §3.6.1 states it: the hash of the secret,
	/// the big-endian counter, and the SharedInfo, in that order.
	fn x963_block(counter: u32, info: &[u8]) -> Vec<u8> {
		Sha3_256::digest([SHARED_SECRET, &counter.to_be_bytes(), info].concat()).to_vec()
	}

	// `EcdhSecret` refuses a shared secret of another width than the field of
	// its curve, so every derivation runs on exactly that width: 32 bytes on
	// secp256k1, and 66 on P-521.
	crate::tb_cases! {
		fn a_shared_secret_of_the_wrong_length_is_refused(
			(refused, width): (Option<KdfError>, ReceivedExpectedError<usize, usize>)
		) {
			assert!(matches!(refused, Some(KdfError::InvalidSharedSecretLength(found)) if found == width));
		}
		cases {
			short => (
				EcdhSecret::<Secp256k1>::try_from(SecretSlice::from(b"short".to_vec())).err(),
				ReceivedExpectedError { received: 5, expected: 32 },
			),
			long => (
				EcdhSecret::<Secp256k1>::try_from(SecretSlice::from(vec![0x11; 34])).err(),
				ReceivedExpectedError { received: 34, expected: 32 },
			),
			narrow_on_p521 => (
				EcdhSecret::<NistP521>::try_from(SecretSlice::from(vec![0x11; 32])).err(),
				ReceivedExpectedError { received: 32, expected: 66 },
			),
		}
	}

	// A provider derives a key of the length it is asked for. General-purpose
	// HKDF derives 16, 32, and 64-byte keys.
	crate::tb_cases! {
		fn a_dynamic_key_takes_its_length((key, length): (ZeroizingBytes, usize)) {
			assert_eq!(key.len(), length);
		}
		cases {
			hkdf_of_16_octets => (hkdf_key(SHARED_SECRET, 16), 16),
			hkdf_of_32_octets => (hkdf_key(SHARED_SECRET, 32), 32),
			hkdf_of_64_octets => (hkdf_key(SHARED_SECRET, 64), 64),
			x963_of_32_octets => (x963_key(INFO_V1, None), 32),
		}
	}

	// The same inputs derive the same key under HKDF and under X9.63, and
	// X9.63 ignores the salt, so a salted key equals the unsalted key.
	crate::tb_cases! {
		fn two_derivations_give_one_key((first, second): (ZeroizingBytes, ZeroizingBytes)) {
			assert_eq!(first, second);
		}
		cases {
			hkdf_of_the_same_inputs => (hkdf_key(SHARED_SECRET, 32), hkdf_key(SHARED_SECRET, 32)),
			x963_of_the_same_inputs => (x963_key(INFO_V1, None), x963_key(INFO_V1, None)),
			x963_with_and_without_a_salt => (x963_key(INFO_V1, None), x963_key(INFO_V1, Some(salt()))),
		}
	}

	// HKDF binds its IKM and X9.63 binds its info, so another input derives
	// another key.
	crate::tb_cases! {
		fn a_changed_input_gives_another_key((key, changed): (ZeroizingBytes, ZeroizingBytes)) {
			assert_ne!(key, changed);
		}
		cases {
			hkdf_ikm => (hkdf_key(SHARED_SECRET, 32), hkdf_key(b"different_ikm", 32)),
			x963_info => (x963_key(INFO_V1, None), x963_key(INFO_V2, None)),
		}
	}

	// Each provider refuses an output below `MIN_KEY_SIZE`, and the HKDF
	// provider also refuses an output past `MAX_HKDF_OUTPUT_SIZE`. A dual-key
	// size of 65 bytes expands to 130, past the cap, and one of 8 bytes is
	// below the floor.
	crate::tb_cases! {
		fn a_key_outside_the_bounds_is_refused(refused: Option<KdfError>) {
			assert!(matches!(refused, Some(KdfError::DerivationFailed(_))));
		}
		cases {
			hkdf_below_min => HkdfSha3_256::derive_dynamic_key(b"ikm", b"info", None, 8).err(),
			hkdf_above_max => HkdfSha3_256::derive_dynamic_key(b"ikm", b"info", None, 129).err(),
			x963_below_min => X963Sha3_256::derive_dynamic_key(b"ikm", b"info", None, 8).err(),
			hkdf_dual_past_the_cap => HkdfSha3_256::derive_dual_keys::<65>(SHARED_SECRET, INFO_V1, None).err(),
			x963_dual_below_min => X963Sha3_256::derive_dual_keys::<8>(b"ikm", INFO_V1, None).err(),
		}
	}

	// Each derivation matches its reference, built outside the provider. A
	// dual-key pair is one expansion split in half, the encryption key first.
	crate::tb_cases! {
		fn a_derivation_matches_its_reference((derived, reference): (Vec<u8>, Vec<u8>)) {
			assert_eq!(derived, reference);
		}
		cases {
			/// An unsalted key is the RFC 5869 expansion under a salt of zeros
			/// as long as the hash, which `hkdf` 0.12 takes for an absent salt.
			unsalted_hkdf_key => (hkdf_key(b"ikm", 32).to_vec(), hkdf_expansion::<32>(None, b"ikm")),
			/// The HKDF pair is the interoperable ECIES key schedule.
			hkdf_pair_under_a_salt => (hkdf_pair::<32>(b"ikm", Some(salt())), hkdf_expansion::<64>(Some(SALT), b"ikm")),
			/// A dual-key size of 64 bytes expands to 128 bytes, which equals
			/// `MAX_HKDF_OUTPUT_SIZE`.
			hkdf_pair_at_the_cap => (hkdf_pair::<64>(SHARED_SECRET, None), hkdf_expansion::<128>(None, SHARED_SECRET)),
			/// Each X9.63 block is the hash of the secret, the counter, and the
			/// SharedInfo, in that order.
			x963_key_of_one_block => (x963_key(INFO_V1, None).to_vec(), x963_block(1, INFO_V1)),
			/// A pair of 16 octets each splits the first block.
			x963_pair_of_16_octets => (x963_pair::<16>(INFO_V1), x963_block(1, INFO_V1)),
			/// A pair of 32 octets each spans two blocks.
			x963_pair_of_32_octets => (
				x963_pair::<32>(INFO_V1),
				[x963_block(1, INFO_V1), x963_block(2, INFO_V1)].concat(),
			),
			/// A SharedInfo longer than 256 octets derives too, so no fixed
			/// 256-octet buffer bounds the info.
			x963_pair_under_a_large_shared_info => (
				x963_pair::<32>(&LARGE_INFO),
				[x963_block(1, &LARGE_INFO), x963_block(2, &LARGE_INFO)].concat(),
			),
		}
	}

	/// A salt below `MIN_SALT_ENTROPY_BYTES` is refused where its `KdfSalt` is
	/// built, before any KDF reads it, and the refusal names both lengths.
	#[test]
	fn a_salt_below_the_floor_is_refused_at_kdf_salt() {
		let refused = KdfSalt::try_from(b"ab".as_slice());
		assert!(matches!(refused, Err(KdfError::SaltTooShort { actual: 2, minimum: 16 })));
	}
}
