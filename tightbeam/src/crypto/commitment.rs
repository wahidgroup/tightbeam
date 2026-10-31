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
//! wire format is unchanged. `CommitmentSalt::commit` owns the preimage layout
//! and its mode byte.

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

	/// Compute the commitment digest of `data` under this salt.
	///
	/// # Preimage
	///
	/// - [`CommitmentSalt::Plain`]: `H(mode || data)`.
	/// - Hiding salt: `H(mode || len(salt) || salt || data)`, where `len(salt)`
	///   is an 8-byte big-endian length.
	///
	/// The mode byte separates the two forms, so a hiding commitment and a
	/// plain digest of the same body are different values and neither verifies
	/// as the other. The length frame keeps distinct `(salt, data)` pairs from
	/// sharing a preimage. The preimage streams into the hasher, so prepending
	/// the prefix costs no copy of the body.
	pub(crate) fn commit<D>(&self, data: impl AsRef<[u8]>) -> Result<DigestInfo>
	where
		D: Digest + AssociatedOid,
	{
		let mut hasher = D::new();
		match self {
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
		let commitment = salt.commit::<D>(&message)?;
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

		let recomputed = self.salt.commit::<D>(&self.message)?;
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
	use crate::error::ReceivedExpectedError;
	use crate::testing::TestResult;

	#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
	struct Body {
		value: u8,
	}

	impl Message for Body {
		type Profile = crate::crypto::profiles::TightbeamProfile;
	}

	/// The commitment and the opening of a body of `value` under `salt`.
	fn commit(value: u8, salt: &[u8]) -> (DigestInfo, Opening) {
		let proved = Opening::prove::<Sha3_256, _>(&Body { value }, salt);
		proved.expect("a test salt is empty or meets the floor")
	}

	/// The DER of a body of `value`.
	fn body(value: u8) -> Vec<u8> {
		crate::encode(&Body { value }).expect("a test body encodes")
	}

	/// The mode byte separates the two forms, so a plain digest of a body
	/// never doubles as a commitment over it.
	#[test]
	fn a_plain_commitment_is_not_the_digest_of_the_body() -> TestResult {
		let plain = crate::utils::digest::<Sha3_256>(body(1))?;
		let (commitment, _) = commit(1, &[]);
		assert_ne!(commitment.digest.as_bytes(), plain.digest.as_bytes());
		Ok(())
	}

	// The hasher reads the preimage in pieces, so the layout exists in no
	// single buffer. Each row pins the documented bytes of one mode against a
	// concatenation built by hand: the mode byte then the body, or the mode
	// byte, the length, the salt, then the body.
	crate::tb_cases! {
		fn a_commitment_digests_its_documented_preimage((salt, preimage): (Vec<u8>, Vec<u8>)) -> TestResult {
			let by_hand = crate::utils::digest::<Sha3_256>(&preimage)?;
			let (commitment, _) = commit(1, &salt);
			assert_eq!(commitment.digest.as_bytes(), by_hand.digest.as_bytes());
			Ok(())
		}
		cases {
			plain => (Vec::new(), [&[PLAIN_MODE][..], body(1).as_slice()].concat()),
			hiding => (
				vec![7; MIN_SALT_SIZE],
				[
					&[HIDING_MODE][..],
					&(MIN_SALT_SIZE as u64).to_be_bytes(),
					&[7; MIN_SALT_SIZE],
					body(1).as_slice(),
				]
				.concat(),
			),
		}
	}

	/// A salt changes the commitment of the same body.
	#[test]
	fn salt_hides_commitment() {
		let (unsalted, _) = commit(1, &[]);
		let (salted, _) = commit(1, &[7u8; 32]);
		assert_ne!(unsalted.digest.as_bytes(), salted.digest.as_bytes());
	}

	/// A salt below the floor hides nothing, so it never commits, and the
	/// refusal names both lengths.
	#[test]
	fn a_salt_below_the_floor_is_refused() {
		let result = Opening::prove::<Sha3_256, _>(&Body { value: 1 }, [7u8; MIN_SALT_SIZE - 1]);
		let lengths = ReceivedExpectedError { received: MIN_SALT_SIZE - 1, expected: MIN_SALT_SIZE };
		assert!(matches!(result, Err(TightBeamError::InvalidSaltLength(found)) if found == lengths));
	}

	/// A salt of `0x01` octets over `02 03` and a salt one `0x02` octet longer
	/// over `03` share one raw concatenation, and the length framing keeps
	/// their commitments apart.
	#[test]
	fn salt_framing_prevents_prefix_collision() -> TestResult {
		let mut longer_salt = [1u8; MIN_SALT_SIZE + 1];
		longer_salt[MIN_SALT_SIZE] = 2;

		let split_salt = CommitmentSalt::parse([1u8; MIN_SALT_SIZE])?.commit::<Sha3_256>([2, 3])?;
		let split_data = CommitmentSalt::parse(longer_salt)?.commit::<Sha3_256>([3])?;
		assert_ne!(split_salt.digest.as_bytes(), split_data.digest.as_bytes());
		Ok(())
	}

	// An opening verifies against the commitment of value 9 under a salt of
	// `0x03` octets when it opens that value under that salt, and an opening
	// of another value or another salt fails to verify against it.
	crate::tb_cases! {
		fn an_opening_verifies_for_its_own_input((value, salt, verifies): (u8, [u8; 32], bool)) -> TestResult {
			let (commitment, _) = commit(9, &[3; 32]);
			let (_, opening) = commit(value, &salt);

			let verified = opening.verify::<Sha3_256>(&commitment)?;
			assert_eq!(verified, verifies);
			Ok(())
		}
		cases {
			the_same_input => (9, [3; 32], true),
			another_salt => (9, [4; 32], false),
			another_value => (1, [3; 32], false),
		}
	}
}
