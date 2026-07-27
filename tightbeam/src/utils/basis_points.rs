//! Basis points representation for probabilities, percentages, and rates.
//!
//! Basis points (bps) are a common unit in finance and statistics for expressing
//! fractional values where 1 basis point = 0.01% or 1/10000.
//!
//! # Examples
//!
//! ```
//! use tightbeam::utils::BasisPoints;
//!
//! // Compile-time validated constants
//! const ALWAYS: BasisPoints = BasisPoints::new(10000);  // 100%
//! const HALF: BasisPoints = BasisPoints::new(5000);     // 50%
//! const NEVER: BasisPoints = BasisPoints::new(0);       // 0%
//!
//! // Runtime usage
//! let prob = BasisPoints::new(7500);  // 75%
//! assert_eq!(prob.get(), 7500);
//! assert_eq!(prob.as_percentage(), 75.0);
//! ```

use crate::der::{Decode, Encode, Reader, Writer};

/// Error for values outside the 0-10000 basis-point range
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasisPointsOutOfRange;

impl core::fmt::Display for BasisPointsOutOfRange {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "value outside the 0-10000 basis-point range")
	}
}

impl core::error::Error for BasisPointsOutOfRange {}

/// Probability in basis points (0-10000, where 10000 = 100%)
///
/// Enforces valid range at compile time via const constructor.
/// Provides deterministic integer-only math for no_std compatibility.
///
/// # Validation
///
/// - Values must be in range [0, 10000]
/// - When used in `const` contexts, invalid values trigger compile errors
/// - Runtime validation still occurs via assertion
///
/// # Use Cases
///
/// - Fault injection probabilities (testing)
/// - Rate limiting thresholds
/// - Statistical sampling rates
/// - Quality-of-service parameters
/// - Any fractional value requiring deterministic math
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BasisPoints(u16);

/// Round-half-up for non-negative values already range-checked by the caller.
///
/// `f64::round` lives on `std` (core has no float intrinsics), so add-then-
/// truncate keeps this module no_std-compatible.
fn round_non_negative(value: f64) -> u16 {
	(value + 0.5) as u16
}

impl BasisPoints {
	/// Maximum value (100%)
	pub const MAX: Self = Self(10000);

	/// Minimum value (0%)
	pub const MIN: Self = Self(0);

	/// Create a new BasisPoints value (0-10000) from a literal
	///
	/// Intended for `const` contexts and literal arguments, where an
	/// out-of-range value fails at compile time. Runtime-valued inputs
	/// MUST use [`TryFrom<u16>`] or [`new_saturating`](Self::new_saturating)
	/// instead, since those cannot panic.
	///
	/// # Panics
	///
	/// Panics if value > 10000: at compile time in const contexts, at
	/// runtime otherwise.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::utils::BasisPoints;
	///
	/// const VALID: BasisPoints = BasisPoints::new(5000);       // OK
	/// // const INVALID: BasisPoints = BasisPoints::new(10001); // Compile error
	/// ```
	pub const fn new(value: u16) -> Self {
		assert!(value <= 10000, "BasisPoints must be 0-10000");
		Self(value)
	}

	/// Get the raw value (0-10000)
	pub const fn get(self) -> u16 {
		self.0
	}

	/// Convert to percentage (0.0-100.0)
	///
	/// # Example
	///
	/// ```
	/// use tightbeam::utils::BasisPoints;
	///
	/// let bps = BasisPoints::new(7500);
	/// assert_eq!(bps.as_percentage(), 75.0);
	/// ```
	pub fn as_percentage(self) -> f64 {
		self.0 as f64 / 100.0
	}

	/// Convert to fraction (0.0-1.0)
	///
	/// # Example
	///
	/// ```
	/// use tightbeam::utils::BasisPoints;
	///
	/// let bps = BasisPoints::new(2500);
	/// assert_eq!(bps.as_fraction(), 0.25);
	/// ```
	pub fn as_fraction(self) -> f64 {
		self.0 as f64 / 10000.0
	}

	/// Create from percentage (0.0-100.0)
	///
	/// # Errors
	///
	/// Returns [`BasisPointsOutOfRange`] if percentage is NaN or outside
	/// the [0.0, 100.0] range.
	///
	/// # Example
	///
	/// ```
	/// use tightbeam::utils::{BasisPoints, BasisPointsOutOfRange};
	///
	/// # fn main() -> Result<(), BasisPointsOutOfRange> {
	/// let bps = BasisPoints::from_percentage(75.5)?;
	/// assert_eq!(bps.get(), 7550);
	/// # Ok(())
	/// # }
	/// ```
	pub fn from_percentage(percentage: f64) -> Result<Self, BasisPointsOutOfRange> {
		if !(0.0..=100.0).contains(&percentage) {
			return Err(BasisPointsOutOfRange);
		}

		Ok(Self(round_non_negative(percentage * 100.0)))
	}

	/// Create from fraction (0.0-1.0)
	///
	/// # Errors
	///
	/// Returns [`BasisPointsOutOfRange`] if fraction is NaN or outside
	/// the [0.0, 1.0] range.
	///
	/// # Example
	///
	/// ```
	/// use tightbeam::utils::{BasisPoints, BasisPointsOutOfRange};
	///
	/// # fn main() -> Result<(), BasisPointsOutOfRange> {
	/// let bps = BasisPoints::from_fraction(0.75)?;
	/// assert_eq!(bps.get(), 7500);
	/// # Ok(())
	/// # }
	/// ```
	pub fn from_fraction(fraction: f64) -> Result<Self, BasisPointsOutOfRange> {
		if !(0.0..=1.0).contains(&fraction) {
			return Err(BasisPointsOutOfRange);
		}

		Ok(Self(round_non_negative(fraction * 10000.0)))
	}

	/// Create a new BasisPoints value, saturating at MAX (10000)
	///
	/// Unlike `new()`, this does not panic for out-of-range values.
	/// Values > 10000 are clamped to 10000.
	///
	/// # Example
	///
	/// ```
	/// use tightbeam::utils::BasisPoints;
	///
	/// let clamped = BasisPoints::new_saturating(15000);
	/// assert_eq!(clamped.get(), 10000);
	/// ```
	pub const fn new_saturating(value: u16) -> Self {
		if value > 10000 {
			Self(10000)
		} else {
			Self(value)
		}
	}
}

impl Default for BasisPoints {
	/// Default is 0 basis points (0%)
	fn default() -> Self {
		Self::MIN
	}
}

impl TryFrom<u16> for BasisPoints {
	type Error = BasisPointsOutOfRange;

	fn try_from(value: u16) -> Result<Self, Self::Error> {
		if value > 10000 {
			return Err(BasisPointsOutOfRange);
		}

		Ok(Self(value))
	}
}

impl From<BasisPoints> for u16 {
	fn from(bps: BasisPoints) -> u16 {
		bps.get()
	}
}

// DER encoding: BasisPoints encodes as an INTEGER (u16)
impl Encode for BasisPoints {
	fn encoded_len(&self) -> crate::der::Result<der::Length> {
		self.0.encoded_len()
	}

	fn encode(&self, encoder: &mut impl Writer) -> crate::der::Result<()> {
		self.0.encode(encoder)
	}
}

impl<'a> Decode<'a> for BasisPoints {
	fn decode<R: Reader<'a>>(reader: &mut R) -> crate::der::Result<Self> {
		let value = u16::decode(reader)?;
		Ok(Self::new_saturating(value))
	}
}

impl core::fmt::Display for BasisPoints {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{}bps ({}%)", self.0, self.as_percentage())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn new_validates_range() {
		assert_eq!(BasisPoints::new(0).get(), 0);
		assert_eq!(BasisPoints::new(5000).get(), 5000);
		assert_eq!(BasisPoints::new(10000).get(), 10000);
	}

	#[test]
	#[should_panic(expected = "BasisPoints must be 0-10000")]
	fn new_panics_above_max() {
		BasisPoints::new(10001);
	}

	#[test]
	fn const_validation_works() {
		const ZERO: BasisPoints = BasisPoints::new(0);
		const MAX: BasisPoints = BasisPoints::new(10000);
		assert_eq!(ZERO.get(), 0);
		assert_eq!(MAX.get(), 10000);
	}

	#[test]
	fn percentage_conversion() {
		assert_eq!(BasisPoints::new(0).as_percentage(), 0.0);
		assert_eq!(BasisPoints::new(5000).as_percentage(), 50.0);
		assert_eq!(BasisPoints::new(10000).as_percentage(), 100.0);
		assert_eq!(BasisPoints::new(7550).as_percentage(), 75.5);
	}

	#[test]
	fn fraction_conversion() {
		assert_eq!(BasisPoints::new(0).as_fraction(), 0.0);
		assert_eq!(BasisPoints::new(5000).as_fraction(), 0.5);
		assert_eq!(BasisPoints::new(10000).as_fraction(), 1.0);
		assert_eq!(BasisPoints::new(2500).as_fraction(), 0.25);
	}

	#[test]
	fn from_percentage() {
		assert_eq!(BasisPoints::from_percentage(0.0), Ok(BasisPoints::new(0)));
		assert_eq!(BasisPoints::from_percentage(50.0), Ok(BasisPoints::new(5000)));
		assert_eq!(BasisPoints::from_percentage(100.0), Ok(BasisPoints::new(10000)));
		assert_eq!(BasisPoints::from_percentage(75.5), Ok(BasisPoints::new(7550)));
	}

	#[test]
	fn from_percentage_rejects_out_of_range() {
		assert_eq!(BasisPoints::from_percentage(-0.1), Err(BasisPointsOutOfRange));
		assert_eq!(BasisPoints::from_percentage(100.1), Err(BasisPointsOutOfRange));
		assert_eq!(BasisPoints::from_percentage(f64::NAN), Err(BasisPointsOutOfRange));
	}

	#[test]
	fn from_fraction() {
		assert_eq!(BasisPoints::from_fraction(0.0), Ok(BasisPoints::new(0)));
		assert_eq!(BasisPoints::from_fraction(0.5), Ok(BasisPoints::new(5000)));
		assert_eq!(BasisPoints::from_fraction(1.0), Ok(BasisPoints::new(10000)));
		assert_eq!(BasisPoints::from_fraction(0.25), Ok(BasisPoints::new(2500)));
	}

	#[test]
	fn from_fraction_rejects_out_of_range() {
		assert_eq!(BasisPoints::from_fraction(-0.1), Err(BasisPointsOutOfRange));
		assert_eq!(BasisPoints::from_fraction(1.1), Err(BasisPointsOutOfRange));
		assert_eq!(BasisPoints::from_fraction(f64::NAN), Err(BasisPointsOutOfRange));
	}

	#[test]
	fn try_from_validates_range() {
		assert_eq!(BasisPoints::try_from(0u16), Ok(BasisPoints::MIN));
		assert_eq!(BasisPoints::try_from(5000u16), Ok(BasisPoints::new(5000)));
		assert_eq!(BasisPoints::try_from(10000u16), Ok(BasisPoints::MAX));
		assert_eq!(BasisPoints::try_from(10001u16), Err(BasisPointsOutOfRange));
	}

	#[test]
	fn display_format() {
		assert_eq!(format!("{}", BasisPoints::new(5000)), "5000bps (50%)");
		assert_eq!(format!("{}", BasisPoints::new(7550)), "7550bps (75.5%)");
	}

	#[test]
	fn constants() {
		assert_eq!(BasisPoints::MAX.get(), 10000);
		assert_eq!(BasisPoints::MIN.get(), 0);
	}

	#[test]
	fn default_is_zero() {
		assert_eq!(BasisPoints::default().get(), 0);
	}

	#[test]
	fn ordering() {
		assert!(BasisPoints::new(1000) < BasisPoints::new(5000));
		assert!(BasisPoints::new(10000) > BasisPoints::new(0));
		assert_eq!(BasisPoints::new(5000), BasisPoints::new(5000));
	}

	#[test]
	fn new_saturating_clamps() {
		assert_eq!(BasisPoints::new_saturating(0).get(), 0);
		assert_eq!(BasisPoints::new_saturating(5000).get(), 5000);
		assert_eq!(BasisPoints::new_saturating(10000).get(), 10000);
		assert_eq!(BasisPoints::new_saturating(10001).get(), 10000);
		assert_eq!(BasisPoints::new_saturating(u16::MAX).get(), 10000);
	}

	#[test]
	fn der_roundtrip() {
		use crate::der::{Decode, Encode};

		let original = BasisPoints::new(7500);
		let mut buf = [0u8; 16];
		let encoded = original.encode_to_slice(&mut buf);
		assert!(encoded.is_ok());

		let decoded = BasisPoints::from_der(encoded.as_ref().map(|s| *s).unwrap_or(&[]));
		assert!(decoded.is_ok());
		assert_eq!(decoded.ok(), Some(original));
	}

	#[test]
	fn der_decode_saturates() {
		use crate::der::Encode;

		// Encode a u16 value > 10000 directly
		let over_max: u16 = 15000;
		let mut buf = [0u8; 16];
		let encoded = over_max.encode_to_slice(&mut buf);
		assert!(encoded.is_ok());

		// Decode as BasisPoints - should saturate to 10000
		let decoded = BasisPoints::from_der(encoded.as_ref().map(|s| *s).unwrap_or(&[]));
		assert!(decoded.is_ok());
		assert_eq!(decoded.ok(), Some(BasisPoints::MAX));
	}
}
