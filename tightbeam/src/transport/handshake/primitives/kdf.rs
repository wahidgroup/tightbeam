//! Multi-input key derivation functions for hybrid key agreement.
//!
//! The primitives serve protocols that combine two or more shared secrets,
//! such as ECDH with a KEM in PQXDH.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::fmt;
use core::mem::size_of;

use crate::crypto::kdf::{KdfFunction, KdfSalt};
use crate::crypto::profiles::CryptoProvider;
use crate::transport::handshake::error::HandshakeError;
use crate::zeroize::Zeroizing;
use crate::ZeroizingBytes;

#[cfg(any(feature = "transport-hpke", mux_rekey))]
use crate::crypto::kdf::KdfError;

/// The salt of a key derivation over the handshake randoms,
/// `client_random || server_random`.
///
/// The HPKE handshake derives under it, and every rekey epoch derives under
/// the fresh pair its exchange drew, so the layout has one home.
#[cfg(any(feature = "transport-hpke", mux_rekey))]
pub(crate) struct RandomsSalt(Zeroizing<[u8; 64]>);

#[cfg(any(feature = "transport-hpke", mux_rekey))]
impl RandomsSalt {
	/// Lays `client_random` ahead of `server_random`.
	pub(crate) fn new(client_random: &[u8; 32], server_random: &[u8; 32]) -> Self {
		let mut salt = Zeroizing::new([0u8; 64]);
		let randoms = client_random.iter().chain(server_random);
		for (octet, random) in salt.iter_mut().zip(randoms) {
			*octet = *random;
		}
		Self(salt)
	}

	/// This salt as the [`KdfSalt`] of one derivation.
	///
	/// # Errors
	///
	/// - [`KdfError::SaltTooShort`] -- the two randoms are shorter than the salt floor.
	pub(crate) fn as_kdf_salt(&self) -> Result<KdfSalt<'_>, KdfError> {
		KdfSalt::try_from(self.0.as_slice())
	}
}

/// The domain separator bound into the KDF expand step.
///
/// Two derivations that share input key material stay independent when their
/// labels differ. It is a distinct type from [`KdfSalt`] for the reason that
/// type states.
///
/// # Sources
///
/// - RFC 5869 § 3.2, the info label and domain separation:
///   <https://datatracker.ietf.org/doc/html/rfc5869#section-3.2>
#[derive(Clone, Copy, Debug)]
pub struct KdfInfo<'a>(&'a [u8]);

impl<'a> KdfInfo<'a> {
	/// Wraps `info` as the label for one derivation.
	pub fn new(info: &'a (impl AsRef<[u8]> + ?Sized)) -> Self {
		Self(info.as_ref())
	}

	/// The label bytes, for the provider call that consumes them.
	#[must_use]
	pub fn as_bytes(&self) -> &'a [u8] {
		self.0
	}
}

/// One stage of [`kdf_chain`]: the input key material and its label.
///
/// The pair travels as a named struct, so a stage list names the role of
/// each of its two byte slices, and a swap of the two shows in the source.
#[derive(Clone, Copy)]
pub struct KdfStage<'a> {
	/// The input key material that this stage extracts from.
	pub input: &'a [u8],
	/// The label that separates this stage from every other.
	pub info: KdfInfo<'a>,
}

// The `input` is key material, so `Debug` prints its length and the public
// label only (CWE-532).
impl fmt::Debug for KdfStage<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("KdfStage")
			.field("input_len", &self.input.len())
			.field("info", &self.info)
			.finish()
	}
}

/// Multi-input HKDF: the provider KDF over the length-prefixed concatenation
/// of the secrets.
///
/// Each input carries its length as a big-endian `u32` prefix, so the
/// concatenation is unambiguous ("ab"+"cd" against "abc"+"d").
///
/// # Errors
///
/// - [`HandshakeError::IntegerOutOfRange`] -- an input exceeds `u32::MAX`
///   bytes, or the sum passes the `isize::MAX` bytes a `Vec` can hold.
/// - [`HandshakeError::KdfError`] -- the KDF refused `key_size`.
pub fn multi_input_kdf<P: CryptoProvider>(
	inputs: &[&[u8]],
	salt: KdfSalt<'_>,
	info: KdfInfo<'_>,
	key_size: usize,
) -> Result<ZeroizingBytes, HandshakeError> {
	let combined = length_prefixed_inputs(inputs)?;

	Ok(P::Kdf::derive_dynamic_key(&combined, info.as_bytes(), Some(salt), key_size)?)
}

/// Concatenates the inputs, each behind its length prefix, into one wiping
/// buffer.
///
/// [`multi_input_kdf`] states the framing. The buffer holds secret material,
/// so it is reserved at its final length before the first byte lands. It
/// allocates once, and no reallocation frees an unwiped copy (CWE-226).
///
/// # Errors
///
/// - [`HandshakeError::IntegerOutOfRange`] -- an input exceeds `u32::MAX`
///   bytes, or the sum passes the `isize::MAX` bytes a `Vec` can hold.
fn length_prefixed_inputs(inputs: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>, HandshakeError> {
	let prefix = size_of::<u32>();
	let capacity = isize::MAX.unsigned_abs();
	let total = inputs.iter().try_fold(0usize, |total, input| {
		let len = u32::try_from(input.len()).map_err(|_| HandshakeError::IntegerOutOfRange)?;
		let framed = prefix.checked_add(len as usize).and_then(|framed| total.checked_add(framed));
		let bounded = framed.filter(|total| *total <= capacity);
		bounded.ok_or(HandshakeError::IntegerOutOfRange)
	})?;

	let mut combined = Zeroizing::new(Vec::with_capacity(total));
	for input in inputs {
		// The fold proved each length fits a `u32`, so the cast is lossless.
		let len = input.len() as u32;
		combined.extend_from_slice(&len.to_be_bytes());
		combined.extend_from_slice(input);
	}

	Ok(combined)
}

/// Chained KDF: each stage's output becomes the next stage's salt
/// (PQXDH-style).
///
/// Each stage derives 32 bytes, and an empty stage list yields an empty key.
///
/// # Errors
///
/// - [`HandshakeError::KdfError`] -- the KDF refused a stage.
/// - [`HandshakeError::InsufficientSaltEntropy`] -- a stage derived fewer
///   bytes than the salt floor that the next stage reads.
pub fn kdf_chain<P: CryptoProvider>(
	stages: &[KdfStage<'_>],
	initial_salt: KdfSalt<'_>,
) -> Result<ZeroizingBytes, HandshakeError> {
	if stages.is_empty() {
		return Ok(Zeroizing::new(Vec::new()));
	}

	// Each intermediate output is key material, so each stage holds it in a
	// `Zeroizing` buffer that wipes it before the allocator reuses it.
	let mut current = Zeroizing::new(initial_salt.as_bytes().to_vec());
	for stage in stages {
		let salt = KdfSalt::try_from(current.as_slice())?;
		current = P::Kdf::derive_dynamic_key(stage.input, stage.info.as_bytes(), Some(salt), 32)?;
	}

	Ok(current)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::testing::TestResult;

	/// The salt of the derivations below, 32 octets of `0xaa`.
	const SALT: &[u8] = &[0xaa; 32];

	// A multi-input derivation frames each input behind its length, so it
	// derives the requested length from inputs of one length and of two.
	crate::tb_cases! {
		fn a_multi_input_derivation_is_as_long_as_its_key_size((first, second): (&[u8], &[u8])) -> TestResult {
			let salt = KdfSalt::try_from(SALT)?;
			let key = multi_input_kdf::<DefaultCryptoProvider>(&[first, second], salt, KdfInfo::new(b"test-info"), 32)?;
			assert_eq!(key.len(), 32);
			Ok(())
		}
		cases {
			over_inputs_of_one_length => (&[0x42; 32], &[0x99; 32]),
			over_inputs_of_two_lengths => (&[0x42; 16], &[0x99; 48]),
		}
	}

	// Each stage of a KDF chain derives 32 bytes, so the key of one stage or
	// more is 32 bytes.
	crate::tb_cases! {
		fn a_kdf_chain_derives_32_bytes((stages, salt): (&[KdfStage<'_>], &[u8])) -> TestResult {
			let salt = KdfSalt::try_from(salt)?;
			let key = kdf_chain::<DefaultCryptoProvider>(stages, salt)?;
			assert_eq!(key.len(), 32);
			Ok(())
		}
		cases {
			over_two_stages => (
				&[
					KdfStage { input: &[0x11; 32], info: KdfInfo::new(b"stage1") },
					KdfStage { input: &[0x22; 32], info: KdfInfo::new(b"stage2") },
				],
				&[0xff; 32],
			),
			over_one_stage => (&[KdfStage { input: &[0x42; 32], info: KdfInfo::new(b"single") }], SALT),
		}
	}

	/// [`length_prefixed_inputs`] allocates the combined buffer once at its
	/// final length, so no reallocation frees an unwiped copy of the inputs
	/// (CWE-226). A buffer grown by `extend_from_slice` from an empty `Vec`
	/// would over-allocate to the next power of two, so its capacity would
	/// exceed its length.
	#[test]
	fn the_combined_kdf_buffer_is_allocated_once() -> TestResult {
		let first = [0u8; 10];
		let second = [0u8; 20];

		let combined = length_prefixed_inputs(&[&first, &second])?;
		assert_eq!(combined.len(), 38);
		assert_eq!(combined.capacity(), combined.len());
		Ok(())
	}

	/// The `Debug` of a KDF stage prints its input length in place of the
	/// input key material (CWE-532).
	#[test]
	fn kdf_stage_debug_omits_the_input_bytes() {
		let input = [0xABu8; 32];
		let stage = KdfStage { input: &input, info: KdfInfo::new(b"stage") };

		let rendered = format!("{stage:?}");
		assert!(!rendered.contains("171"));
		assert!(rendered.contains("input_len"));
		assert!(rendered.contains("32"));
	}
}
