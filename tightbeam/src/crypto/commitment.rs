//! Hiding message commitments.
//!
//! A bare `H(message)` digest is *binding* but not *hiding*: a low-entropy body
//! can be recovered by brute-forcing candidate preimages against the digest that
//! travels in cleartext metadata. A commitment salts the body with a secret
//! blinding value so the published digest reveals nothing about the body until
//! the opening `(salt, message)` is disclosed.
//!
//! The commitment value is `H(salt || DER(message))` and is stored in the
//! existing message integrity field, so the wire format is unchanged. An empty
//! salt reproduces the plain message digest used for corruption detection only.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::crypto::hash::Digest;
use crate::der::oid::AssociatedOid;
use crate::error::Result;
use crate::{DigestInfo, Message};

/// Compute the commitment digest `H(salt || data)`.
///
/// An empty `salt` yields `H(data)`, matching a plain message digest. The salt
/// is concatenated without length framing, so a deployment MUST use a
/// fixed-length salt to avoid prefix ambiguity.
pub(crate) fn commit_digest<D>(salt: &[u8], data: &[u8]) -> Result<DigestInfo>
where
	D: Digest + AssociatedOid,
{
	let mut buffer = Vec::with_capacity(salt.len() + data.len());
	buffer.extend_from_slice(salt);
	buffer.extend_from_slice(data);

	crate::utils::digest::<D>(&buffer)
}

/// Constant-time byte-slice equality.
fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
	if lhs.len() != rhs.len() {
		return false;
	}

	let mut difference = 0u8;
	for (left, right) in lhs.iter().zip(rhs.iter()) {
		difference |= left ^ right;
	}

	difference == 0
}

/// The opening of a message commitment: the secret blinding salt and the
/// committed message body.
///
/// Disclosing an `Opening` lets any holder of the commitment verify it via
/// [`Opening::verify`], realizing a disclose-then-verify proof.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Opening {
	salt: Vec<u8>,
	message: Vec<u8>,
}

impl Opening {
	/// Produce a commitment over `message` together with its opening.
	///
	/// The returned [`DigestInfo`] is the public commitment to publish; the
	/// [`Opening`] is the secret proof to disclose during verification. A
	/// high-entropy `salt` makes the commitment hiding.
	pub fn prove<D, M>(message: &M, salt: impl AsRef<[u8]>) -> Result<(DigestInfo, Self)>
	where
		D: Digest + AssociatedOid,
		M: Message,
	{
		let message = crate::encode(message)?;
		let salt = salt.as_ref().to_vec();
		let commitment = commit_digest::<D>(&salt, &message)?;
		Ok((commitment, Self { salt, message }))
	}

	/// Verify this opening against a commitment in constant time.
	///
	/// Returns `false` when the commitment algorithm does not match `D` or when
	/// the recomputed digest differs.
	pub fn verify<D>(&self, commitment: &DigestInfo) -> Result<bool>
	where
		D: Digest + AssociatedOid,
	{
		if commitment.algorithm.oid != D::OID {
			return Ok(false);
		}

		let recomputed = commit_digest::<D>(&self.salt, &self.message)?;
		Ok(constant_time_eq(recomputed.digest.as_bytes(), commitment.digest.as_bytes()))
	}

	/// The blinding salt.
	pub fn salt(&self) -> &[u8] {
		&self.salt
	}

	/// The DER-encoded committed message body.
	pub fn message(&self) -> &[u8] {
		&self.message
	}
}

#[cfg(all(test, feature = "sha3"))]
mod tests {
	use super::*;
	use crate::crypto::hash::Sha3_256;
	use crate::der::Sequence;

	#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
	struct Body {
		value: u8,
	}

	impl Message for Body {
		type Profile = crate::crypto::profiles::TightbeamProfile;
	}

	fn commit(value: u8, salt: &[u8]) -> Result<(DigestInfo, Opening)> {
		Opening::prove::<Sha3_256, _>(&Body { value }, salt)
	}

	#[test]
	fn empty_salt_matches_plain_digest() -> Result<()> {
		let encoded = crate::encode(&Body { value: 1 })?;
		let plain = crate::utils::digest::<Sha3_256>(&encoded)?;
		let (commitment, _) = commit(1, &[])?;
		assert_eq!(commitment.digest.as_bytes(), plain.digest.as_bytes());
		Ok(())
	}

	#[test]
	fn salt_hides_commitment() -> Result<()> {
		let (unsalted, _) = commit(1, &[])?;
		let (salted, _) = commit(1, &[7u8; 32])?;
		assert_ne!(unsalted.digest.as_bytes(), salted.digest.as_bytes());
		Ok(())
	}

	#[test]
	fn opening_verification() -> Result<()> {
		// (commit_value, commit_salt, open_value, open_salt, expected)
		let cases = [
			(9u8, [3u8; 32], 9u8, [3u8; 32], true),
			(9, [3u8; 32], 9, [4u8; 32], false),
			(1, [5u8; 32], 2, [5u8; 32], false),
		];

		for (commit_value, commit_salt, open_value, open_salt, expected) in cases {
			let (commitment, _) = commit(commit_value, &commit_salt)?;
			let (_, opening) = commit(open_value, &open_salt)?;
			assert_eq!(opening.verify::<Sha3_256>(&commitment)?, expected);
		}
		Ok(())
	}
}
