//! Helpers that read published test vectors and fix the random draws of a
//! known answer, and the published vectors that more than one suite runs.
//!
//! [`patterned`] builds a long input of counting octets for a round-trip test.

pub mod ml_kem;
pub mod rfc3394;
pub mod rfc5869;

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

/// `len` octets that count up from zero to 250 and then start again at zero.
///
/// The period, 251, is the largest prime below 256, so the pattern repeats out
/// of step with every block of a power-of-two width.
pub fn patterned(len: usize) -> Vec<u8> {
	(0..251).cycle().take(len).collect()
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

#[cfg(test)]
mod tests {
	#[cfg(feature = "random")]
	use crate::random::RngCore;
	#[cfg(feature = "random")]
	use crate::testing::TestResult;

	use super::patterned;

	#[cfg(feature = "random")]
	use super::{PublishedDraw, SeededStream};

	/// The pattern counts from zero to 250 and then starts again at zero.
	#[test]
	fn the_pattern_wraps_to_zero_after_250() {
		let pattern = patterned(253);
		assert_eq!(pattern[249..], [249, 250, 0, 1]);
	}

	/// A seeded stream fills each draw with the byte after the last one, so
	/// from the seed 0 a `u32` reads as four ones and the next `u64` as eight
	/// twos.
	#[cfg(feature = "random")]
	#[test]
	fn a_seeded_stream_fills_each_draw_with_the_next_byte() {
		let mut stream = SeededStream(0);
		let drawn = (stream.next_u32(), stream.next_u64());
		assert_eq!(drawn, (0x0101_0101, 0x0202_0202_0202_0202));
	}

	/// A published draw hands out its octets in order: a `u32` reads the
	/// first four little-endian, a `u64` the next eight, and a fill the four
	/// after them.
	#[cfg(feature = "random")]
	#[test]
	fn a_published_draw_hands_out_its_octets_in_order() -> TestResult {
		let mut draw = PublishedDraw((0..16).collect());
		let mut filled = [0; 4];

		let drawn = (draw.next_u32(), draw.next_u64());
		draw.try_fill_bytes(&mut filled)?;

		assert_eq!((drawn, filled), ((0x0302_0100, 0x0b0a_0908_0706_0504), [12, 13, 14, 15]));
		Ok(())
	}
}
