//! Multi-input key derivation functions for hybrid key agreement.
//!
//! The module provides composable KDF primitives for protocols that combine
//! several shared secrets, for example ECDH with a KEM in PQXDH.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::fmt;
use core::mem::size_of;

use crate::crypto::kdf::KdfFunction;
use crate::crypto::profiles::CryptoProvider;
use crate::transport::handshake::error::HandshakeError;
use crate::zeroize::Zeroizing;
use crate::ZeroizingBytes;

/// Per-session randomness mixed into the KDF extract step.
///
/// HKDF takes a salt and a label, and both arrive as bytes. A caller that
/// holds them as two slices can exchange them and still compile, so each
/// role travels as its own type and the exchange has no call site at which
/// to occur.
///
/// # Sources
///
/// - RFC 5869 § 2.2, the extract step and its salt:
///   <https://datatracker.ietf.org/doc/html/rfc5869#section-2.2>
#[derive(Clone, Copy, Debug)]
pub struct KdfSalt<'a>(&'a [u8]);

impl<'a> KdfSalt<'a> {
	/// Wraps `salt` as the salt for one derivation.
	pub fn new(salt: &'a (impl AsRef<[u8]> + ?Sized)) -> Self {
		Self(salt.as_ref())
	}

	/// The salt bytes, for the provider call that consumes them.
	#[must_use]
	pub fn as_bytes(&self) -> &'a [u8] {
		self.0
	}
}

/// Domain separator bound into the KDF expand step.
///
/// Two derivations that share input key material stay independent when their
/// labels differ, so the label is what makes one derivation safe beside
/// another. It is a distinct type from [`KdfSalt`] for the reason that type
/// states.
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
/// The pair travels as a named struct so a stage list cannot silently swap
/// the two byte slices it holds.
#[derive(Clone, Copy)]
pub struct KdfStage<'a> {
	/// Input key material this stage extracts from.
	pub input: &'a [u8],
	/// The label separating this stage from every other.
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
/// Each input is prefixed with its length as a big-endian `u32`, so a
/// concatenation is unambiguous (for example "ab"+"cd" against "abc"+"d").
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

	Ok(P::Kdf::derive_dynamic_key(
		&combined,
		info.as_bytes(),
		Some(salt.as_bytes()),
		key_size,
	)?)
}

/// Concatenates the inputs, each behind its length prefix, into one wiping
/// buffer.
///
/// [`multi_input_kdf`] states the framing. The buffer holds secret material
/// and is reserved at its final length before the first byte lands, so it is
/// allocated once and a reallocation cannot free an unwiped copy on the way
/// (CWE-226).
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
pub fn kdf_chain<P: CryptoProvider>(
	stages: &[KdfStage<'_>],
	initial_salt: KdfSalt<'_>,
) -> Result<ZeroizingBytes, HandshakeError> {
	if stages.is_empty() {
		return Ok(Zeroizing::new(Vec::new()));
	}

	// Each intermediate output is key material. Keep every stage in a
	// Zeroizing buffer so nothing lingers in the allocator.
	let mut current = Zeroizing::new(initial_salt.as_bytes().to_vec());
	for stage in stages {
		current = P::Kdf::derive_dynamic_key(stage.input, stage.info.as_bytes(), Some(&current), 32)?;
	}

	Ok(current)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;

	#[test]
	fn test_multi_input_kdf() -> Result<(), Box<dyn core::error::Error>> {
		let input1 = [0x42u8; 32];
		let input2 = [0x99u8; 32];
		let salt_bytes = [0xAAu8; 32];
		let salt = KdfSalt::new(&salt_bytes);
		let info = KdfInfo::new(b"test-info");

		let result = multi_input_kdf::<DefaultCryptoProvider>(&[&input1, &input2], salt, info, 32);
		assert!(result.is_ok());

		let key = result?;
		assert_eq!(key.len(), 32);

		Ok(())
	}

	#[test]
	fn test_multi_input_kdf_different_lengths() {
		let input1 = [0x42u8; 16];
		let input2 = [0x99u8; 48];
		let salt_bytes = [0xAAu8; 32];
		let salt = KdfSalt::new(&salt_bytes);
		let info = KdfInfo::new(b"test-info");

		let result = multi_input_kdf::<DefaultCryptoProvider>(&[&input1, &input2], salt, info, 32);
		assert!(result.is_ok());
	}

	#[test]
	fn test_kdf_chain() -> Result<(), Box<dyn core::error::Error>> {
		let input1 = [0x11u8; 32];
		let input2 = [0x22u8; 32];
		let initial_salt = [0xFFu8; 32];
		let first = KdfStage { input: &input1, info: KdfInfo::new(b"stage1") };
		let second = KdfStage { input: &input2, info: KdfInfo::new(b"stage2") };

		let result = kdf_chain::<DefaultCryptoProvider>(&[first, second], KdfSalt::new(&initial_salt));
		assert!(result.is_ok());

		let key = result?;
		assert_eq!(key.len(), 32);

		Ok(())
	}

	#[test]
	fn test_kdf_chain_single_stage() {
		let input = [0x42u8; 32];
		let salt = [0xAAu8; 32];

		let only = KdfStage { input: &input, info: KdfInfo::new(b"single") };
		let result = kdf_chain::<DefaultCryptoProvider>(&[only], KdfSalt::new(&salt));
		assert!(result.is_ok());
	}

	/// The combined buffer is allocated once at its final length, so no
	/// reallocation frees an unwiped copy of the inputs (CWE-226). A buffer
	/// grown by `extend_from_slice` from an empty `Vec` would over-allocate to
	/// the next power of two, so its capacity would exceed its length.
	#[test]
	fn the_combined_kdf_buffer_is_allocated_once() -> Result<(), Box<dyn core::error::Error>> {
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
