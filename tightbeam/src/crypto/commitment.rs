//! Hiding message commitments.
//!
//! A bare `H(message)` digest is *binding* but not *hiding*: a low-entropy body
//! can be recovered by brute-forcing candidate preimages against the digest that
//! travels in cleartext metadata. A commitment salts the body with a secret
//! blinding value so the published digest reveals nothing about the body until
//! the opening `(salt, message)` is disclosed.
//!
//! The commitment value goes in the existing message integrity field, so the
//! wire format is unchanged. Its preimage starts with a mode byte, so a
//! hiding commitment and a plain digest of the same body are different values
//! and neither verifies as the other.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::constants::MIN_SALT_SIZE;
use crate::crypto::hash::{ConstantTimeDigest, Digest};
use crate::crypto::secret::SecretSlice;
use crate::der::oid::AssociatedOid;
use crate::error::{Result, TightBeamError};
use crate::{DigestInfo, Message};

/// Preimage prefix of a commitment that only binds its body.
const PLAIN_MODE: u8 = 0x00;

/// Preimage prefix of a commitment that hides its body behind a salt.
const HIDING_MODE: u8 = 0x01;

/// A blinding salt carrying at least [`MIN_SALT_SIZE`] bytes.
///
/// The field is private and [`CommitmentSalt::parse`] is the only thing that
/// mints one, so a salt too short to hide a body has no representation. A
/// public payload here would put the length rule back at every call site.
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
#[derive(Debug)]
pub struct HidingSalt(SecretSlice<u8>);

impl HidingSalt {
	/// Read the salt bytes for the duration of `read`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SecretUnavailable`] when the salt was already taken.
	pub fn with<R>(&self, read: impl FnOnce(&[u8]) -> R) -> Result<R> {
		Ok(self.0.with(read)?)
	}
}

/// The blinding salt of a message commitment.
///
/// A commitment hides its body only when the salt carries enough entropy, so
/// a salt below [`MIN_SALT_SIZE`] never becomes one. An empty salt names the
/// plain-digest mode, which binds the body without hiding it.
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
#[derive(Debug)]
pub enum CommitmentSalt {
	/// No salt. The commitment binds the body and reveals a digest of it.
	Plain,
	/// A blinding salt of at least [`MIN_SALT_SIZE`] bytes.
	Hiding(HidingSalt),
}

impl CommitmentSalt {
	/// Read a caller's salt.
	///
	/// An empty salt selects [`CommitmentSalt::Plain`], and any other salt
	/// hides the body.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InvalidSaltLength`] when a non-empty salt is
	///   shorter than [`MIN_SALT_SIZE`], which would not hide the body.
	pub fn parse(salt: impl AsRef<[u8]>) -> Result<Self> {
		let salt = salt.as_ref();
		if salt.is_empty() {
			return Ok(Self::Plain);
		}
		if salt.len() < MIN_SALT_SIZE {
			return Err(TightBeamError::InvalidSaltLength((salt.len(), MIN_SALT_SIZE).into()));
		}

		Ok(Self::Hiding(HidingSalt(SecretSlice::from(salt.to_vec()))))
	}
}

/// Compute the commitment digest over `salt` and `data`.
///
/// The preimage is `H(mode || data)` for [`CommitmentSalt::Plain`] and
/// `H(mode || len(salt) || salt || data)` for a hiding salt, with an 8-byte
/// big-endian length. The mode byte separates the two, and the length frame
/// keeps distinct `(salt, data)` pairs from sharing a preimage.
///
/// The preimage is streamed into the hasher, so no copy of the body is made
/// to prepend the prefix to it.
pub(crate) fn commit_digest<D>(salt: &CommitmentSalt, data: impl AsRef<[u8]>) -> Result<DigestInfo>
where
	D: Digest + AssociatedOid,
{
	let mut hasher = D::new();
	match salt {
		CommitmentSalt::Plain => hasher.update([PLAIN_MODE]),
		CommitmentSalt::Hiding(salt) => salt.with(|salt| {
			hasher.update([HIDING_MODE]);
			hasher.update((salt.len() as u64).to_be_bytes());
			hasher.update(salt);
		})?,
	}

	hasher.update(data.as_ref());
	crate::utils::digest_info::<D>(hasher)
}

/// The opening of a message commitment: the secret blinding salt and the
/// committed message body.
///
/// Disclosing an `Opening` lets any holder of the commitment verify it via
/// [`Opening::verify`], realizing a disclose-then-verify proof.
#[derive(Debug)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Opening {
	salt: CommitmentSalt,
	message: Vec<u8>,
}

impl Opening {
	/// Produce a commitment over `message` together with its opening.
	///
	/// The returned [`DigestInfo`] is the public commitment to publish, and
	/// the [`Opening`] is the secret proof to disclose during verification. A
	/// salt of at least [`MIN_SALT_SIZE`] bytes makes the commitment hiding,
	/// and an empty salt commits in plain-digest mode.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InvalidSaltLength`] when the salt is too short to hide the body.
	pub fn prove<D, M>(message: &M, salt: impl AsRef<[u8]>) -> Result<(DigestInfo, Self)>
	where
		D: Digest + AssociatedOid,
		M: Message,
	{
		let message = crate::encode(message)?;
		let salt = CommitmentSalt::parse(salt)?;
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
		Ok(recomputed.digest_matches(commitment))
	}

	/// The blinding salt.
	pub fn salt(&self) -> &CommitmentSalt {
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

	// The mode byte separates the two forms, so a plain digest of a body
	// never doubles as a commitment over it.
	#[test]
	fn a_plain_commitment_is_not_the_digest_of_the_body() -> Result<()> {
		let encoded = crate::encode(&Body { value: 1 })?;
		let plain = crate::utils::digest::<Sha3_256>(&encoded)?;

		let (commitment, _) = commit(1, &[])?;
		assert_ne!(commitment.digest.as_bytes(), plain.digest.as_bytes());
		Ok(())
	}

	// The hasher is fed in pieces, so the preimage layout is no longer
	// visible as one buffer. These pin the documented bytes against a
	// concatenation built by hand.
	#[test]
	fn a_plain_preimage_is_the_mode_byte_then_the_body() -> Result<()> {
		let encoded = crate::encode(&Body { value: 1 })?;
		let mut expected = vec![PLAIN_MODE];
		expected.extend_from_slice(&encoded);

		let (commitment, _) = commit(1, &[])?;
		let by_hand = crate::utils::digest::<Sha3_256>(&expected)?;
		assert_eq!(commitment.digest.as_bytes(), by_hand.digest.as_bytes());
		Ok(())
	}

	#[test]
	fn a_hiding_preimage_is_the_mode_byte_the_length_the_salt_then_the_body() -> Result<()> {
		let salt = [7u8; MIN_SALT_SIZE];
		let encoded = crate::encode(&Body { value: 1 })?;
		let mut expected = vec![HIDING_MODE];
		expected.extend_from_slice(&(salt.len() as u64).to_be_bytes());
		expected.extend_from_slice(&salt);
		expected.extend_from_slice(&encoded);

		let (commitment, _) = commit(1, &salt)?;
		let by_hand = crate::utils::digest::<Sha3_256>(&expected)?;
		assert_eq!(commitment.digest.as_bytes(), by_hand.digest.as_bytes());
		Ok(())
	}

	#[test]
	fn salt_hides_commitment() -> Result<()> {
		let (unsalted, _) = commit(1, &[])?;
		let (salted, _) = commit(1, &[7u8; 32])?;
		assert_ne!(unsalted.digest.as_bytes(), salted.digest.as_bytes());
		Ok(())
	}

	// A salt below the floor hides nothing, so it never commits.
	#[test]
	fn a_salt_below_the_floor_is_refused() {
		let result = commit(1, &[7u8; MIN_SALT_SIZE - 1]);
		assert!(matches!(result, Err(TightBeamError::InvalidSaltLength(_))));
	}

	#[test]
	fn salt_framing_prevents_prefix_collision() -> Result<()> {
		// Raw concatenation collides into one preimage, and length framing
		// must not.
		let split_salt = commit_digest::<Sha3_256>(&CommitmentSalt::parse([1u8; MIN_SALT_SIZE])?, [2, 3])?;
		let mut longer_salt = [1u8; MIN_SALT_SIZE + 1];
		longer_salt[MIN_SALT_SIZE] = 2;

		let split_data = commit_digest::<Sha3_256>(&CommitmentSalt::parse(longer_salt)?, [3])?;
		assert_ne!(split_salt.digest.as_bytes(), split_data.digest.as_bytes());
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
