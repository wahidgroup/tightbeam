//! Helpers that read published test vectors and fix the random draws of a
//! known answer, and the published vectors that more than one suite runs.

pub mod ml_kem;

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

/// A random source that draws the octets a published vector names, in order,
/// so an operation that draws from it draws the scalars or seeds of the
/// vector. A draw past the last octet panics.
#[cfg(feature = "random")]
pub struct PublishedDraw(
	/// The octets left to draw.
	pub Vec<u8>,
);

#[cfg(feature = "random")]
impl RngCore for PublishedDraw {
	fn next_u32(&mut self) -> u32 {
		rand_core::impls::next_u32_via_fill(self)
	}

	fn next_u64(&mut self) -> u64 {
		rand_core::impls::next_u64_via_fill(self)
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		let drawn: Vec<u8> = self.0.drain(..dest.len()).collect();
		dest.copy_from_slice(&drawn);
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
		self.fill_bytes(dest);
		Ok(())
	}
}

#[cfg(feature = "random")]
impl rand_core::CryptoRng for PublishedDraw {}
