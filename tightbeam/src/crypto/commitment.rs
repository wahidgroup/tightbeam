//! Hiding message commitments.
//!
//! A bare `H(message)` digest is *binding* only. It is not *hiding*, because
//! an attacker can recover a low-entropy body by brute-forcing candidate
//! preimages against the digest that travels in cleartext metadata.
//!
//! A commitment salts the body with a secret blinding value, so the published
//! digest reveals nothing about the body until the opening `(salt, message)`
//! is disclosed.
//!
//! # Wire format
//!
//! The commitment value goes in the existing message integrity field, so the
//! wire format is unchanged. `commit_digest` owns the preimage layout and its
//! mode byte.

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
/// The field is private and [`CommitmentSalt::parse`] is the only
/// constructor, so a salt too short to hide a body has no representation. A
/// public payload would repeat the length rule at every call site.
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
#[derive(Debug)]
pub struct HidingSalt(SecretSlice<u8>);

impl HidingSalt {
	/// Read the salt bytes for the duration of `read`.
	pub fn with<R>(&self, read: impl FnOnce(&[u8]) -> R) -> R {
		self.0.with(|salt| read(salt))
	}
}

/// The blinding salt of a message commitment.
///
/// A commitment hides its body only when the salt carries enough entropy, so
/// only a salt of at least [`MIN_SALT_SIZE`] bytes becomes a hiding salt. An
/// empty salt names the plain-digest mode, which binds the body without
/// hiding it.
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
#[derive(Debug)]
pub enum CommitmentSalt {
	/// The commitment has no salt, so it binds the body and reveals a digest of
	/// it.
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
	/// - [`TightBeamError::InvalidSaltLength`] when a non-empty salt is shorter
	///   than [`MIN_SALT_SIZE`], which would not hide the body.
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
/// # Preimage
///
/// - [`CommitmentSalt::Plain`]: `H(mode || data)`.
/// - Hiding salt: `H(mode || len(salt) || salt || data)`, where `len(salt)` is
///   an 8-byte big-endian length.
///
/// The mode byte separates the two forms, so a hiding commitment and a plain
/// digest of the same body are different values and neither verifies as the
/// other. The length frame keeps distinct `(salt, data)` pairs from sharing a
/// preimage. The preimage streams into the hasher, so prepending the prefix
/// costs no copy of the body.
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
		}),
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

	/// Return the blinding salt of this opening.
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

	// The hasher reads the preimage in pieces, so the layout exists in no
	// single buffer. These tests pin the documented bytes against a
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
