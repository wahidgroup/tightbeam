//! Helpers that read published test vectors and fix the random draws of a
//! known answer.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "random")]
use crate::random::RngCore;

/// The bytes a hex string names.
pub fn unhex(hex: &str) -> Vec<u8> {
	let digits = hex.as_bytes().chunks(2);
	let bytes = digits.map(|pair| {
		let pair = core::str::from_utf8(pair).expect("a vector is ASCII");
		u8::from_str_radix(pair, 16).expect("a vector is hex")
	});
	bytes.collect()
}

/// A random source that every run repeats: each draw fills its buffer with
/// the byte after the last one, from the seed on, so a known answer can name
/// every draw.
///
/// The OS source draws fresh bytes, so a known answer of a seal draws from
/// this source in its place.
#[cfg(feature = "random")]
pub struct SeededStream(
	/// The last byte drawn.
	pub u8,
);

#[cfg(feature = "random")]
impl RngCore for SeededStream {
	fn next_u32(&mut self) -> u32 {
		rand_core::impls::next_u32_via_fill(self)
	}

	fn next_u64(&mut self) -> u64 {
		rand_core::impls::next_u64_via_fill(self)
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		self.0 = self.0.wrapping_add(1);
		dest.fill(self.0);
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
		self.fill_bytes(dest);
		Ok(())
	}
}

#[cfg(feature = "random")]
impl rand_core::CryptoRng for SeededStream {}
