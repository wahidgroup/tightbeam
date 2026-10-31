//! HMAC and HKDF over the core of a digest, whose keyed pads, buffered input,
//! pseudorandom key, and output blocks a drop wipes.
//!
//! The handshake schedule, the house KDF, and the HPKE KDF derive here.
//! `hmac` 0.12.1, `hkdf` 0.12.4, and `digest` 0.10.7 leave four copies of
//! that key material in plain arrays:
//!
//! - `SimpleHmac` holds the outer pad, the key XOR `opad`, and its `finalize` consumes the value.
//! - `Hkdf::new` drops the pseudorandom key that its extract step returns.
//! - `Hkdf::expand` clones the keyed HMAC into each step, and holds the output block of the step before.
//! - A digest buffers the input that waits for a whole block, such as the
//!   input key material, and drops the buffer as it is.
//!
//! # Wipes
//!
//! NIST SP 800-56C Rev. 2 § 5.1 asks that a key-derivation key be destroyed
//! after its use. Here each copy lives in a buffer whose drop is its wipe:
//!
//! - A [`SecretBlock`] holds a keyed pad, the pseudorandom key, or an output block.
//! - A [`SecretBuffer`] holds the input that waits for a whole block, beside
//!   the core each hash drives through [`HashCore`].
//!
//! The core holds the state that absorbed the key XOR `ipad`, and the drop
//! of the core wipes it under the provider contract:
//!
//! - The house SHA3 cores wipe it, which [`crate::crypto::hash`] asserts,
//!   and `DigestProvider::Digest` asks it of a provider.
//! - The SHA-256 and SHA-512 cores of `sha2` 0.10.9, which HPKE derives
//!   over, hold it in plain words with private fields, so it drops as it is.
//!
//! # Sources
//!
//! - RFC 2104 § 2, HMAC: <https://datatracker.ietf.org/doc/html/rfc2104#section-2>
//! - RFC 5869 § 2, HKDF: <https://datatracker.ietf.org/doc/html/rfc5869#section-2>
//! - NIST SP 800-56C Rev. 2 § 5.1, the destruction of a key-derivation key:
//!   <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf#page=25>
//! - NIST example values, whose HMAC-SHA3-256 samples the tests run:
//!   <https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values>

use core::mem::needs_drop;
use core::num::NonZeroUsize;

use digest::core_api::{BlockSizeUser, Buffer, CoreProxy, FixedOutputCore, OutputSizeUser, UpdateCore};

use crate::crypto::common::generic_array::{ArrayLength, GenericArray};
use crate::crypto::common::typenum::Unsigned;
use crate::crypto::hash::{HashCore, Sha3_256};
use crate::crypto::hkdf::InvalidLength;
#[cfg(feature = "hpke")]
use crate::crypto::hkdf::InvalidPrkLength;
use crate::zeroize::Zeroize;

/// The octet that RFC 2104 § 2 XORs into the key of the inner hash.
const IPAD: u8 = 0x36;

/// The octet that RFC 2104 § 2 XORs into the key of the outer hash.
const OPAD: u8 = 0x5c;

/// The block width of the core of the digest `D`.
type BlockSize<D> = <<D as CoreProxy>::Core as BlockSizeUser>::BlockSize;

/// The output width of the core of the digest `D`.
type OutputSize<D> = <<D as CoreProxy>::Core as OutputSizeUser>::OutputSize;

/// Octets of key material as wide as `N`, which a drop wipes.
#[derive(Clone)]
pub(crate) struct SecretBlock<N: ArrayLength<u8>>(GenericArray<u8, N>);

impl<N: ArrayLength<u8>> SecretBlock<N> {
	/// The octets of this block.
	pub(crate) fn as_slice(&self) -> &[u8] {
		self.0.as_slice()
	}

	/// This block with `pad` XORed into each octet.
	fn xor(&self, pad: u8) -> Self {
		let mut padded = self.clone();
		padded.0.iter_mut().for_each(|octet| *octet ^= pad);
		padded
	}
}

impl<N: ArrayLength<u8>> Drop for SecretBlock<N> {
	fn drop(&mut self) {
		self.0.as_mut_slice().zeroize();
	}
}

/// The block buffer of the core `C`, which holds the input that waits for a
/// whole block, and which a drop wipes whole.
#[derive(Clone)]
struct SecretBuffer<C: HashCore>(Buffer<C>);

impl<C: HashCore> Drop for SecretBuffer<C> {
	fn drop(&mut self) {
		// The pad lends the whole block, the octets before the position too.
		self.0.pad_with_zeros().as_mut_slice().zeroize();
	}
}

// A `SecretBlock` and a `SecretBuffer` hold plain octets, so the wipe is the
// one step of each drop. A type that loses its wipe has no drop step, and
// fails here.
const _: () = {
	type Core = <Sha3_256 as CoreProxy>::Core;
	assert!(needs_drop::<SecretBlock<<Core as BlockSizeUser>::BlockSize>>());
	assert!(needs_drop::<SecretBuffer<Core>>());
};

/// A hash over the core of the digest `D`, whose buffered input a drop wipes.
pub(crate) struct ZeroizingHash<D: CoreProxy<Core: HashCore>> {
	/// The block function and its state.
	core: D::Core,
	/// The input that waits for a whole block.
	buffer: SecretBuffer<D::Core>,
}

impl<D: CoreProxy<Core: HashCore>> Clone for ZeroizingHash<D> {
	fn clone(&self) -> Self {
		Self { core: self.core.clone(), buffer: self.buffer.clone() }
	}
}

impl<D: CoreProxy<Core: HashCore>> ZeroizingHash<D> {
	/// The hash of no input.
	pub(crate) fn new() -> Self {
		Self { core: D::Core::default(), buffer: SecretBuffer(Buffer::<D::Core>::default()) }
	}

	/// The hash of `data` alone.
	fn digest(data: &[u8]) -> SecretBlock<OutputSize<D>> {
		Self::new().chain_update(data).finalize()
	}

	/// Feed `data` to the hash.
	pub(crate) fn update(&mut self, data: &[u8]) {
		let Self { core, buffer } = self;
		buffer.0.digest_blocks(data, |blocks| core.update_blocks(blocks));
	}

	/// This hash, once it took `data`.
	pub(crate) fn chain_update(mut self, data: &[u8]) -> Self {
		self.update(data);
		self
	}

	/// The hash of every octet this hash took.
	pub(crate) fn finalize(mut self) -> SecretBlock<OutputSize<D>> {
		let mut output = SecretBlock(GenericArray::default());
		self.core.finalize_fixed_core(&mut self.buffer.0, &mut output.0);
		output
	}
}

/// HMAC over the core of the digest `D`, whose keyed pads and buffered text a
/// drop wipes (RFC 2104 § 2).
pub(crate) struct ZeroizingHmac<D: CoreProxy<Core: HashCore>> {
	/// The inner hash, which took the key XOR `ipad` first.
	inner: ZeroizingHash<D>,
	/// The key XOR `opad`, which the outer hash takes first.
	outer_pad: SecretBlock<BlockSize<D>>,
}

impl<D: CoreProxy<Core: HashCore>> Clone for ZeroizingHmac<D> {
	fn clone(&self) -> Self {
		Self { inner: self.inner.clone(), outer_pad: self.outer_pad.clone() }
	}
}

impl<D: CoreProxy<Core: HashCore>> ZeroizingHmac<D> {
	/// The HMAC under `key`.
	///
	/// This hashes a key wider than one block of `D` first, and then pads the
	/// key with zeros to one block (RFC 2104 § 2).
	pub(crate) fn new(key: &[u8]) -> Self {
		let hashed = (key.len() > BlockSize::<D>::USIZE).then(|| ZeroizingHash::<D>::digest(key));
		let key = hashed.as_ref().map_or(key, SecretBlock::as_slice);

		let mut padded = SecretBlock(GenericArray::<u8, BlockSize<D>>::default());
		padded.0.iter_mut().zip(key).for_each(|(slot, octet)| *slot = *octet);
		let inner = ZeroizingHash::new().chain_update(padded.xor(IPAD).as_slice());
		Self { inner, outer_pad: padded.xor(OPAD) }
	}

	/// Feed `data` to the HMAC.
	pub(crate) fn update(&mut self, data: &[u8]) {
		self.inner.update(data);
	}

	/// This HMAC, once it took `data`.
	pub(crate) fn chain_update(mut self, data: &[u8]) -> Self {
		self.update(data);
		self
	}

	/// The tag over every octet this HMAC took,
	/// `H(K XOR opad || H(K XOR ipad || text))`.
	pub(crate) fn finalize(self) -> SecretBlock<OutputSize<D>> {
		let inner_hash = self.inner.finalize();
		let outer = ZeroizingHash::<D>::new().chain_update(self.outer_pad.as_slice());
		outer.chain_update(inner_hash.as_slice()).finalize()
	}
}

/// HKDF over [`ZeroizingHmac`], whose pseudorandom key and output blocks a
/// drop wipes (RFC 5869 § 2).
pub(crate) struct ZeroizingHkdf<D: CoreProxy<Core: HashCore>> {
	/// The HMAC under the pseudorandom key, which each step of the expansion
	/// clones.
	prk: ZeroizingHmac<D>,
}

impl<D: CoreProxy<Core: HashCore>> ZeroizingHkdf<D> {
	/// HKDF-Extract of `ikm` under `salt`, the pseudorandom key
	/// (RFC 5869 § 2.2).
	pub(crate) fn extract(salt: &[u8], ikm: &[u8]) -> SecretBlock<OutputSize<D>> {
		ZeroizingHmac::<D>::new(salt).chain_update(ikm).finalize()
	}

	/// HKDF-Extract of `ikm` under `salt`, ready to expand (RFC 5869 § 2.2).
	pub(crate) fn new(salt: &[u8], ikm: &[u8]) -> Self {
		let prk = Self::extract(salt, ikm);
		Self { prk: ZeroizingHmac::new(prk.as_slice()) }
	}

	/// The expansion of `prk`, a pseudorandom key (RFC 5869 § 2.3).
	///
	/// # Errors
	///
	/// - [`InvalidPrkLength`] -- `prk` is shorter than one output block of `D`.
	#[cfg(feature = "hpke")]
	pub(crate) fn from_prk(prk: &[u8]) -> Result<Self, InvalidPrkLength> {
		if prk.len() < OutputSize::<D>::USIZE {
			return Err(InvalidPrkLength);
		}

		Ok(Self { prk: ZeroizingHmac::new(prk) })
	}

	/// HKDF-Expand of `info` into all of `okm` (RFC 5869 § 2.3).
	///
	/// # Errors
	///
	/// - [`InvalidLength`] -- `okm` is longer than 255 output blocks of `D`.
	pub(crate) fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), InvalidLength> {
		let width = NonZeroUsize::new(OutputSize::<D>::USIZE).ok_or(InvalidLength)?;
		let limit = width.get().saturating_mul(usize::from(u8::MAX));
		if okm.len() > limit {
			return Err(InvalidLength);
		}

		// Each block is T(i) = HMAC(PRK, T(i - 1) || info || i), and T(0) is
		// empty.
		let mut previous: Option<SecretBlock<OutputSize<D>>> = None;
		for (block, counter) in okm.chunks_mut(width.get()).zip(1..=u8::MAX) {
			let chained = previous.as_ref().map_or(&[][..], SecretBlock::as_slice);
			let step = self.prk.clone().chain_update(chained).chain_update(info);
			let output = step.chain_update(&[counter]).finalize();
			block.iter_mut().zip(output.as_slice()).for_each(|(slot, octet)| *slot = *octet);
			previous = Some(output);
		}

		Ok(())
	}
}

#[cfg(all(test, feature = "hex"))]
mod tests {
	use super::*;
	use crate::hex;

	/// The key of a NIST HMAC sample, the octets from 0 counting up, `len`
	/// of them.
	fn sample_key(len: usize) -> Vec<u8> {
		(0..=u8::MAX).take(len).collect()
	}

	/// The tag of HMAC-SHA3-256 under `key` over `text`.
	fn hmac_sha3_256(key: &[u8], text: &[u8]) -> Vec<u8> {
		let tag = ZeroizingHmac::<Sha3_256>::new(key).chain_update(text).finalize();
		tag.as_slice().to_vec()
	}

	// Each NIST HMAC-SHA3-256 sample keys the MAC with the octets from 0
	// counting up, as many as the sample names, and pins the tag of its text.
	crate::tb_cases! {
		fn hmac_sha3_256_matches_nist((key_len, text, expected): (usize, &[u8], [u8; 32])) {
			let tag = hmac_sha3_256(&sample_key(key_len), text);
			assert_eq!(tag, expected);
		}
		cases {
			/// Sample #1, a key shorter than the 136-octet block.
			sample_1 => (
				32,
				b"Sample message for keylen<blocklen",
				hex!("4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205"),
			),
			/// Sample #2, a key as wide as the block.
			sample_2 => (
				136,
				b"Sample message for keylen=blocklen",
				hex!("68b94e2e538a9be4103bebb5aa016d47961d4d1aa906061313b557f8af2c3faa"),
			),
			/// Sample #3, a key wider than the block, which HMAC hashes first.
			sample_3 => (
				168,
				b"Sample message for keylen>blocklen",
				hex!("9bcf2c238e235c3ce88404e813bd2f3a97185ac6f238c63d6229a00b07974258"),
			),
		}
	}

	/// The expansion refuses an output past 255 output blocks (RFC 5869 § 2.3).
	#[test]
	fn an_expansion_past_255_blocks_is_refused() {
		let hkdf = ZeroizingHkdf::<Sha3_256>::new(b"salt", b"input key material");
		let mut okm = vec![0u8; 255 * 32 + 1];

		let refused = hkdf.expand(b"info", &mut okm);
		assert!(matches!(refused, Err(InvalidLength)));
	}

	/// The expansion refuses a pseudorandom key shorter than one output block
	/// (RFC 5869 § 2.3).
	#[cfg(feature = "hpke")]
	#[test]
	fn a_pseudorandom_key_shorter_than_one_block_is_refused() {
		let refused = ZeroizingHkdf::<Sha3_256>::from_prk(&[0x0b; 31]);
		assert!(matches!(refused, Err(InvalidPrkLength)));
	}

	/// The test cases of RFC 5869 Appendix A that run over SHA-256.
	#[cfg(feature = "secp256k1")]
	mod rfc5869 {
		use super::*;
		use crate::crypto::k256::sha2::Sha256;
		use crate::testing::unhex;
		use crate::testing::vectors::rfc5869::{HkdfVector, RFC_5869_A_1, RFC_5869_A_2, RFC_5869_A_3};

		/// The output of HKDF-SHA-256 over the inputs of `vector`, as many
		/// octets as it names.
		fn hkdf_sha256(vector: &HkdfVector) -> Vec<u8> {
			let mut okm = vec![0u8; vector.length];
			let hkdf = ZeroizingHkdf::<Sha256>::new(&unhex(vector.salt), &unhex(vector.ikm));
			let expanded = hkdf.expand(&unhex(vector.info), &mut okm);
			expanded.expect("a published length lies within 255 blocks");
			okm
		}

		// The zeroizing HKDF over SHA-256 expands each published case to its
		// output keying material.
		crate::tb_cases! {
			fn hkdf_sha256_matches_test(vector: HkdfVector) {
				let okm = hkdf_sha256(&vector);
				assert_eq!(okm, unhex(vector.okm));
			}
			cases {
				/// A.1, the basic case: two output blocks, the last cut short.
				case_1 => RFC_5869_A_1,
				/// A.2, longer inputs and outputs: three output blocks, each
				/// chained on the block before.
				case_2 => RFC_5869_A_2,
				/// A.3, an empty salt and an empty info.
				case_3 => RFC_5869_A_3,
			}
		}
	}
}
