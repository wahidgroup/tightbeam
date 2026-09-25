//! Multi-input key derivation functions for hybrid key agreement.
//!
//! Provides composable KDF primitives for protocols that combine multiple
//! shared secrets (e.g., ECDH + KEM in PQXDH).

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

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
	/// The salt for one derivation.
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
	/// The label for one derivation.
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
#[derive(Clone, Copy, Debug)]
pub struct KdfStage<'a> {
	/// Input key material this stage extracts from.
	pub input: &'a [u8],
	/// The label separating this stage from every other.
	pub info: KdfInfo<'a>,
}

/// Multi-input HKDF: length-prefixed concatenation of secrets, then provider
/// KDF.
///
/// Each input is prefixed with its length as big-endian `u32`, preventing
/// concatenation ambiguity (e.g. "ab"+"cd" vs "abc"+"d").
pub fn multi_input_kdf<P: CryptoProvider>(
	inputs: &[&[u8]],
	salt: KdfSalt<'_>,
	info: KdfInfo<'_>,
	key_size: usize,
) -> Result<ZeroizingBytes, HandshakeError> {
	// Concatenate all inputs with length prefixes. The buffer holds secret
	// material, so it is zeroized on drop.
	let mut combined = Zeroizing::new(Vec::new());
	for input in inputs {
		let len = u32::try_from(input.len()).map_err(|_| HandshakeError::IntegerOutOfRange)?;
		combined.extend_from_slice(&len.to_be_bytes());
		combined.extend_from_slice(input);
	}

	Ok(P::Kdf::derive_dynamic_key(
		&combined,
		info.as_bytes(),
		Some(salt.as_bytes()),
		key_size,
	)?)
}

/// Chained KDF: each stage's output becomes the next stage's salt
/// (PQXDH-style).
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
}
