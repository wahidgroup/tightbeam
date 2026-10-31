//! Basis points representation for probabilities, percentages, and rates.
//!
//! Basis points (bps) are a common unit in finance and statistics for a
//! fractional value, where 1 basis point is 0.01%, or 1/10000.
//!
//! # Examples
//!
//! ```
//! use tightbeam::basis_points::BasisPoints;
//!
//! // Compile-time validated constants
//! const ALWAYS: BasisPoints = tightbeam::bps!(10000);  // 100%
//! const HALF: BasisPoints = tightbeam::bps!(5000);     // 50%
//! const NEVER: BasisPoints = tightbeam::bps!(0);       // 0%
//!
//! // Runtime usage
//! let prob = tightbeam::bps!(7500);  // 75%
//! assert_eq!(prob.get(), 7500);
//! assert_eq!(prob.as_percentage(), 75.0);
//! ```

use crate::der::{Decode, Encode, Reader, Tag, Writer};

/// Shorthand for [`BasisPoints::new::<N>()`](BasisPoints::new).
///
/// The range is also checked here, at the caller, so an out-of-range literal
/// is reported on the line that wrote it rather than inside `new`.
///
/// ## Examples
///
/// ```
/// const HALF: tightbeam::basis_points::BasisPoints = tightbeam::bps!(5000);
/// ```
///
/// ```compile_fail
/// const TOO_HIGH: tightbeam::basis_points::BasisPoints = tightbeam::bps!(10001);
/// ```
#[macro_export]
macro_rules! bps {
	($value:expr $(,)?) => {
		const {
			let value: u16 = $value;
			if value > $crate::basis_points::BasisPoints::MAX.get() {
				::core::panic!("BasisPoints must be 0-10000");
			}

			$crate::basis_points::BasisPoints::new::<{ $value }>()
		}
	};
}

/// The error for a value outside the 0-10000 basis-point range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasisPointsOutOfRange;

impl core::fmt::Display for BasisPointsOutOfRange {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "value outside the 0-10000 basis-point range")
	}
}

impl core::error::Error for BasisPointsOutOfRange {}

/// A probability in basis points, from 0 to 10000, where 10000 is 100%.
///
/// A `u16` value gives deterministic integer-only math for no_std builds.
///
/// # Validation
///
/// - A value must be in the range [0, 10000].
/// - [`BasisPoints::new`] and [`bps!`](crate::bps) reject an out-of-range value at compile time.
/// - `TryFrom<u16>` returns an error for a value known only at run time.
///
/// # Use Cases
///
/// - Fault injection probabilities (testing)
/// - Rate limiting thresholds
/// - Statistical sampling rates
/// - Quality-of-service parameters
/// - Any fractional value that needs deterministic math
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BasisPoints(u16);

/// Round half up a non-negative value that the caller already range-checked.
///
/// `f64::round` lives on `std` (core has no float intrinsics), so add-then-
/// truncate keeps this module no_std-compatible.
fn round_non_negative(value: f64) -> u16 {
	(value + 0.5) as u16
}

impl BasisPoints {
	/// The maximum value, 100%.
	pub const MAX: Self = Self(10000);

	/// The minimum value, 0%.
	pub const MIN: Self = Self(0);

	/// A BasisPoints value (0-10000) known at compile time.
	///
	/// `N` is a const parameter, so a value known only at run time goes through
	/// `TryFrom<u16>` instead. The range check runs in a `const` block, so an
	/// out-of-range `N` is a compile error rather than a run-time panic.
	/// [`bps!`](crate::bps) is shorthand for this.
	pub const fn new<const N: u16>() -> Self {
		const { assert!(N <= Self::MAX.0, "BasisPoints must be 0-10000") };
		Self(N)
	}

	/// The raw value, from 0 to 10000.
	pub const fn get(self) -> u16 {
		self.0
	}

	/// Convert to a percentage, from 0.0 to 100.0.
	///
	/// # Example
	///
	/// ```
	/// use tightbeam::basis_points::BasisPoints;
	///
	/// let bps = tightbeam::bps!(7500);
	/// assert_eq!(bps.as_percentage(), 75.0);
	/// ```
	pub fn as_percentage(self) -> f64 {
		self.0 as f64 / 100.0
	}

	/// Convert to a fraction, from 0.0 to 1.0.
	///
	/// # Example
	///
	/// ```
	/// use tightbeam::basis_points::BasisPoints;
	///
	/// let bps = tightbeam::bps!(2500);
	/// assert_eq!(bps.as_fraction(), 0.25);
	/// ```
	pub fn as_fraction(self) -> f64 {
		self.0 as f64 / 10000.0
	}

	/// Create a value from a percentage in the range 0.0 to 100.0.
	///
	/// # Errors
	///
	/// - [`BasisPointsOutOfRange`] -- `percentage` is NaN or outside the [0.0, 100.0] range.
	///
	/// # Example
	///
	/// ```
	/// use tightbeam::basis_points::{BasisPoints, BasisPointsOutOfRange};
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

	/// Create a value from a fraction in the range 0.0 to 1.0.
	///
	/// # Errors
	///
	/// - [`BasisPointsOutOfRange`] -- `fraction` is NaN or outside the [0.0, 1.0] range.
	///
	/// # Example
	///
	/// ```
	/// use tightbeam::basis_points::{BasisPoints, BasisPointsOutOfRange};
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

	/// Create a value that saturates at `MAX` (10000).
	///
	/// `new` refuses an out-of-range value at compile time. This function takes
	/// a value at run time and clamps a value past 10000 to 10000.
	///
	/// # Example
	///
	/// ```
	/// use tightbeam::basis_points::BasisPoints;
	///
	/// let clamped = BasisPoints::new_saturating(15000);
	/// assert_eq!(clamped.get(), 10000);
	/// ```
	pub const fn new_saturating(value: u16) -> Self {
		if value > Self::MAX.0 {
			Self::MAX
		} else {
			Self(value)
		}
	}

	/// Convert an unsigned value of any width, and saturate at [`Self::MAX`].
	///
	/// The clamp reads the whole value, so a value past `u16::MAX` reads as
	/// [`Self::MAX`] and never wraps into the range.
	///
	/// # Example
	///
	/// ```
	/// use tightbeam::basis_points::BasisPoints;
	///
	/// assert_eq!(BasisPoints::saturating_from(7_500u32).get(), 7_500);
	/// assert_eq!(BasisPoints::saturating_from(65_537u64), BasisPoints::MAX);
	/// ```
	pub fn saturating_from(value: impl Into<u64>) -> Self {
		let value: u64 = value.into();
		u16::try_from(value).map_or(Self::MAX, Self::new_saturating)
	}
}

impl Default for BasisPoints {
	/// The default is 0 basis points, or 0%.
	fn default() -> Self {
		Self::MIN
	}
}

impl TryFrom<u16> for BasisPoints {
	type Error = BasisPointsOutOfRange;

	fn try_from(value: u16) -> Result<Self, Self::Error> {
		if value > Self::MAX.0 {
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

// A `BasisPoints` value encodes as a DER INTEGER, its `u16` value.
impl Encode for BasisPoints {
	fn encoded_len(&self) -> crate::der::Result<der::Length> {
		self.0.encoded_len()
	}

	fn encode(&self, encoder: &mut impl Writer) -> crate::der::Result<()> {
		self.0.encode(encoder)
	}
}

/// An INTEGER past `BasisPoints::MAX` is refused, as `TryFrom<u16>` refuses
/// it, so one decoded value has one encoding.
impl<'a> Decode<'a> for BasisPoints {
	fn decode<R: Reader<'a>>(reader: &mut R) -> crate::der::Result<Self> {
		let value = u16::decode(reader)?;
		Self::try_from(value).map_err(|_| Tag::Integer.value_error())
	}
}

impl core::fmt::Display for BasisPoints {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{}bps ({}%)", self.0, self.as_percentage())
	}
}

#[cfg(test)]
mod tests {
	use core::cmp::Ordering;

	use crate::asn1::admission::fixtures::der_refusal;
	use crate::testing::fixtures::der_round_trip;
	use crate::testing::TestResult;

	use super::*;

	/// No basis points, built in the initializer of a constant.
	const ZERO: BasisPoints = crate::bps!(0);

	/// The full 10000 basis points, built in the initializer of a constant.
	const WHOLE: BasisPoints = crate::bps!(10000);

	/// The outcome of a conversion into basis points.
	type Converted = Result<BasisPoints, BasisPointsOutOfRange>;

	// A value reads back the count of basis points it was built with, whether
	// the macro, a constant, the bounds, or the default built it.
	crate::tb_cases! {
		fn a_value_reads_its_count((bps, count): (BasisPoints, u16)) {
			assert_eq!(bps.get(), count);
		}
		cases {
			macro_zero => (crate::bps!(0), 0),
			macro_half => (crate::bps!(5000), 5000),
			macro_whole => (crate::bps!(10000), 10000),
			const_zero => (ZERO, 0),
			const_whole => (WHOLE, 10000),
			max => (BasisPoints::MAX, 10000),
			min => (BasisPoints::MIN, 0),
			default => (BasisPoints::default(), 0),
		}
	}

	// A count converts into basis points up to 10000 and is refused above it.
	crate::tb_cases! {
		fn a_count_converts_within_the_range((count, expected): (u16, Converted)) {
			assert_eq!(BasisPoints::try_from(count), expected);
		}
		cases {
			zero => (0, Ok(BasisPoints::MIN)),
			half => (5000, Ok(crate::bps!(5000))),
			max => (10000, Ok(BasisPoints::MAX)),
			above_max => (10001, Err(BasisPointsOutOfRange)),
		}
	}

	/// 65,537 narrows to 1 in a `u16`, so a clamp after the narrowing would
	/// answer 1 basis point.
	#[test]
	fn a_value_past_the_u16_range_saturates() {
		assert_eq!(BasisPoints::saturating_from(65_537u64), BasisPoints::MAX);
	}

	/// The decode refuses what the conversion refuses, so INTEGER 65535 is
	/// refused rather than read as 10000.
	#[test]
	fn decode_refuses_above_max() -> TestResult {
		let encoded = u16::MAX.to_der()?;
		let refused = BasisPoints::from_der(&encoded);
		assert_eq!(der_refusal(refused), Some(crate::der::ErrorKind::Value { tag: Tag::Integer }));
		Ok(())
	}

	// A value reads as a percentage, one hundredth of its count.
	crate::tb_cases! {
		fn a_value_reads_as_a_percentage((bps, percentage): (BasisPoints, f64)) {
			assert_eq!(bps.as_percentage(), percentage);
		}
		cases {
			zero => (crate::bps!(0), 0.0),
			half => (crate::bps!(5000), 50.0),
			whole => (crate::bps!(10000), 100.0),
			fractional => (crate::bps!(7550), 75.5),
		}
	}

	// A value reads as a fraction, one ten-thousandth of its count.
	crate::tb_cases! {
		fn a_value_reads_as_a_fraction((bps, fraction): (BasisPoints, f64)) {
			assert_eq!(bps.as_fraction(), fraction);
		}
		cases {
			zero => (crate::bps!(0), 0.0),
			half => (crate::bps!(5000), 0.5),
			whole => (crate::bps!(10000), 1.0),
			quarter => (crate::bps!(2500), 0.25),
		}
	}

	// A percentage from 0 to 100 converts into basis points, and a percentage
	// outside that range, or not a number, is refused.
	crate::tb_cases! {
		fn a_percentage_converts_within_the_range((percentage, expected): (f64, Converted)) {
			assert_eq!(BasisPoints::from_percentage(percentage), expected);
		}
		cases {
			zero => (0.0, Ok(crate::bps!(0))),
			half => (50.0, Ok(crate::bps!(5000))),
			whole => (100.0, Ok(crate::bps!(10000))),
			fractional => (75.5, Ok(crate::bps!(7550))),
			below_zero => (-0.1, Err(BasisPointsOutOfRange)),
			above_whole => (100.1, Err(BasisPointsOutOfRange)),
			not_a_number => (f64::NAN, Err(BasisPointsOutOfRange)),
		}
	}

	// A fraction from 0 to 1 converts into basis points, and a fraction
	// outside that range, or not a number, is refused.
	crate::tb_cases! {
		fn a_fraction_converts_within_the_range((fraction, expected): (f64, Converted)) {
			assert_eq!(BasisPoints::from_fraction(fraction), expected);
		}
		cases {
			zero => (0.0, Ok(crate::bps!(0))),
			half => (0.5, Ok(crate::bps!(5000))),
			whole => (1.0, Ok(crate::bps!(10000))),
			quarter => (0.25, Ok(crate::bps!(2500))),
			below_zero => (-0.1, Err(BasisPointsOutOfRange)),
			above_whole => (1.1, Err(BasisPointsOutOfRange)),
			not_a_number => (f64::NAN, Err(BasisPointsOutOfRange)),
		}
	}

	// A value displays its count and its percentage.
	crate::tb_cases! {
		fn a_value_displays_its_count_and_percentage((bps, text): (BasisPoints, &str)) {
			assert_eq!(bps.to_string(), text);
		}
		cases {
			half => (crate::bps!(5000), "5000bps (50%)"),
			fractional => (crate::bps!(7550), "7550bps (75.5%)"),
		}
	}

	// Values order by their count.
	crate::tb_cases! {
		fn values_order_by_their_count((first, second, order): (BasisPoints, BasisPoints, Ordering)) {
			assert_eq!(first.cmp(&second), order);
		}
		cases {
			less => (crate::bps!(1000), crate::bps!(5000), Ordering::Less),
			greater => (crate::bps!(10000), crate::bps!(0), Ordering::Greater),
			equal => (crate::bps!(5000), crate::bps!(5000), Ordering::Equal),
		}
	}

	// A count above 10000 saturates at 10000, and a count within the range
	// stays as it is.
	crate::tb_cases! {
		fn a_saturating_count_clamps_to_the_range((count, clamped): (u16, u16)) {
			assert_eq!(BasisPoints::new_saturating(count).get(), clamped);
		}
		cases {
			zero => (0, 0),
			half => (5000, 5000),
			whole => (10000, 10000),
			just_above_whole => (10001, 10000),
			largest_count => (u16::MAX, 10000),
		}
	}

	/// A value decodes again from its DER to the value that wrote it.
	#[test]
	fn a_value_round_trips_through_der() {
		let original = crate::bps!(7500);
		assert_eq!(der_round_trip(&original), original);
	}
}
