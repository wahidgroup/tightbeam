//! Digest algorithms used by tightbeam

#[cfg(feature = "sha3")]
pub use sha3::{Sha3_256, Sha3_512};

pub use digest::consts::U32;
pub use digest::Digest;
pub use digest::OutputSizeUser;

use crate::asn1::DigestInfo;
use crate::crypto::subtle::ConstantTimeEq;

/// Constant-time comparison of digest values.
///
/// A digest that gates acceptance is compared against a value an attacker
/// supplies, so a byte-at-a-time timing difference hands that attacker the
/// expected digest one probe per byte. [`subtle`] is the single home for
/// that decision. A hand-rolled accumulate-and-compare loop carries no
/// optimization barrier, so the compiler stays free to short-circuit it.
pub trait ConstantTimeDigest {
	/// Report whether `self` and `other` hold the same digest bytes.
	///
	/// The algorithm identifier is public, and checking it is the caller's
	/// job. Only the digest itself takes the constant-time path.
	fn digest_matches(&self, other: &Self) -> bool;
}

impl ConstantTimeDigest for DigestInfo {
	fn digest_matches(&self, other: &Self) -> bool {
		self.digest.as_bytes().ct_eq(other.digest.as_bytes()).into()
	}
}
