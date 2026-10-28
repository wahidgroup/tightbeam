//! Digest algorithms and constant-time digest comparison for tightbeam.

#[cfg(feature = "sha3")]
pub use sha3::{Sha3_256, Sha3_512};

pub use digest::consts::U32;
pub use digest::core_api::CoreProxy;
pub use digest::Digest;
pub use digest::OutputSizeUser;

use digest::block_buffer::Eager;
use digest::core_api::{BlockSizeUser, BufferKindUser, FixedOutputCore, UpdateCore};
use digest::typenum::{IsLess, NonZero, U256};

use crate::asn1::DigestInfo;
use crate::crypto::subtle::ConstantTimeEq;

#[cfg(feature = "sha3")]
use core::mem::needs_drop;

#[cfg(any(
	feature = "x509",
	feature = "instrument",
	feature = "transport-cms",
	feature = "transport-hpke"
))]
use crate::der::Writer;

/// Constant-time comparison of digest values.
///
/// A digest that gates acceptance is checked against an attacker's value, so a
/// timing difference per byte gives the attacker the expected digest one probe
/// per byte. [`subtle`] is the one home of this comparison, because the
/// compiler may short-circuit a custom loop that has no optimization barrier.
pub trait ConstantTimeDigest {
	/// Report whether `self` and `other` hold the same digest bytes.
	///
	/// The algorithm identifier is public, so the caller checks it. Only the
	/// digest takes the constant-time path.
	fn digest_matches(&self, other: &Self) -> bool;
}

impl ConstantTimeDigest for DigestInfo {
	fn digest_matches(&self, other: &Self) -> bool {
		self.digest.as_bytes().ct_eq(other.digest.as_bytes()).into()
	}
}

/// A DER writer that feeds each encoded octet to the digest it holds, so a
/// value hashes as its encoding with no buffer between the two.
#[cfg(any(
	feature = "x509",
	feature = "instrument",
	feature = "transport-cms",
	feature = "transport-hpke"
))]
pub(crate) struct DigestWriter<D>(pub(crate) D);

#[cfg(any(
	feature = "x509",
	feature = "instrument",
	feature = "transport-cms",
	feature = "transport-hpke"
))]
impl<D: Digest> Writer for DigestWriter<D> {
	fn write(&mut self, slice: &[u8]) -> crate::der::Result<()> {
		self.0.update(slice);
		Ok(())
	}
}

/// The block function of a fixed-output digest, which a caller drives with a
/// block buffer of its own.
///
/// A digest of `digest` 0.10 wraps such a core, which [`CoreProxy::Core`]
/// names, with a buffer that its drop leaves as it is. Every type that meets
/// the bounds implements this trait. The keyed hashes of `crypto::kdf` drive
/// the core with a buffer that wipes on drop (NIST SP 800-56C Rev. 2 § 5.1).
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::hash::{CoreProxy, HashCore, Sha3_256};
///
/// /// Whether a keyed hash can drive the core of `D`.
/// fn drives_its_core<D: CoreProxy<Core: HashCore>>() -> bool {
///     true
/// }
///
/// assert!(drives_its_core::<Sha3_256>());
/// ```
///
/// # Sources
///
/// - NIST SP 800-56C Rev. 2 § 5.1, the destruction of a key-derivation key:
///   <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf#page=25>
pub trait HashCore:
	UpdateCore
	+ FixedOutputCore
	+ BufferKindUser<BufferKind = Eager>
	+ BlockSizeUser<BlockSize: IsLess<U256, Output: NonZero>>
	+ Default
	+ Clone
{
}

impl<C> HashCore for C
where
	C: UpdateCore + FixedOutputCore + BufferKindUser<BufferKind = Eager> + Default + Clone,
	C::BlockSize: IsLess<U256, Output: NonZero>,
{
}

// An HMAC or HKDF holds the Keccak state of its SHA3 core, which wipes on drop
// under the `zeroize` feature of the `sha3` crate alone (NIST SP 800-56C Rev. 2
// § 5.1). The `sha3` feature turns it on through `crypto`, or this check fails.
#[cfg(feature = "sha3")]
const _: () = {
	assert!(needs_drop::<sha3::Sha3_256Core>());
	assert!(needs_drop::<sha3::Sha3_512Core>());
};
