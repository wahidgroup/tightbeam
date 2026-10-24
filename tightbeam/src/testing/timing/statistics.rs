//! Statistical analysis of timing data.
//!
//! `StatisticalAnalyzer` turns observed durations into percentiles, a mean, a
//! median, and confidence intervals for percentile-based WCET analysis.

use crate::der::{Enumerated, Sequence};
use crate::error::TightBeamError;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

/// A statistical model of timing data.
///
/// A custom model implements this trait and plugs in with no change to the
/// core verification logic, as a `JitterCalculator` does.
pub trait StatisticalAnalyzer: Send + Sync + core::fmt::Debug {
	/// Analyzes observed durations, in nanoseconds, into statistical measures
	/// such as percentiles and confidence intervals.
	///
	/// # Errors
	///
	/// - `durations` is empty.
	/// - The analysis needs more samples than `durations` holds.
	fn analyze(&self, durations: &[u64]) -> Result<StatisticalMeasures, TightBeamError>;
}

/// Percentile levels for statistical analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Enumerated)]
#[repr(u8)]
pub enum Percentile {
	/// The 50th percentile, which is the median.
	P50 = 0,
	/// The 90th percentile.
	P90 = 1,
	/// The 95th percentile.
	P95 = 2,
	/// The 99th percentile.
	P99 = 3,
	/// The 99.9th percentile.
	P99_9 = 4,
	/// The 99.99th percentile.
	P99_99 = 5,
}

impl Percentile {
	/// The percentile as a fraction from 0.0 to 1.0.
	pub fn as_float(self) -> f64 {
		match self {
			Percentile::P50 => 0.50,
			Percentile::P90 => 0.90,
			Percentile::P95 => 0.95,
			Percentile::P99 => 0.99,
			Percentile::P99_9 => 0.999,
			Percentile::P99_99 => 0.9999,
		}
	}

	/// The percentile as a fixed-point integer, scaled by 10000, so P95 is 9500
	/// and P99.9 is 9990.
	pub fn as_fixed_point(self) -> u32 {
		match self {
			Percentile::P50 => 5000,
			Percentile::P90 => 9000,
			Percentile::P95 => 9500,
			Percentile::P99 => 9900,
			Percentile::P99_9 => 9990,
			Percentile::P99_99 => 9999,
		}
	}
}

/// Confidence intervals for statistical measures.
#[derive(Debug, Clone, Sequence, PartialEq)]
#[non_exhaustive]
pub struct ConfidenceIntervals {
	/// The confidence level as a fixed-point integer scaled by 10000, so 95% is
	/// 9500.
	pub level: u32,
	/// The lower bound, in nanoseconds.
	pub lower: u64,
	/// The upper bound, in nanoseconds.
	pub upper: u64,
}

/// One percentile and its value, as an ASN.1 sequence.
#[derive(Debug, Clone, Sequence, PartialEq)]
pub struct PercentileValue {
	/// The percentile level.
	pub percentile: Percentile,
	/// The duration at that percentile, in nanoseconds.
	pub value: u64,
}

/// One custom metric and its value, as an ASN.1 sequence.
#[derive(Debug, Clone, Sequence, PartialEq)]
pub struct CustomMetric {
	/// The metric name.
	pub key: String,
	/// The value as a fixed-point integer scaled by 10000.
	pub value: i64,
}

/// Statistical measures from analysis.
#[derive(Debug, Clone, Sequence, PartialEq)]
#[non_exhaustive]
pub struct StatisticalMeasures {
	/// The number of samples.
	pub count: u64,
	/// The mean (average), in nanoseconds.
	pub mean: u64,
	/// The median (50th percentile), in nanoseconds.
	pub median: u64,
	/// The percentiles, such as P95, P99, and P99.9, in nanoseconds.
	pub percentiles: Vec<PercentileValue>,
	/// The confidence intervals, when the sample is large enough.
	#[asn1(optional = "true")]
	pub confidence_intervals: Option<ConfidenceIntervals>,
	/// The custom metrics an analyzer adds beside the standard measures.
	pub custom: Vec<CustomMetric>,
}

/// The default statistical analyzer.
///
/// It computes:
/// - The percentiles P50, P90, P95, P99, P99.9, and P99.99.
/// - The mean and the median.
/// - A simple 95% confidence interval of the mean, from 30 samples on.
#[derive(Default, Debug, Clone, Copy)]
pub struct DefaultStatisticalAnalyzer;

impl StatisticalAnalyzer for DefaultStatisticalAnalyzer {
	fn analyze(&self, durations: &[u64]) -> Result<StatisticalMeasures, TightBeamError> {
		if durations.is_empty() {
			return Err(TightBeamError::InvalidMetadata);
		}

		let count = durations.len();
		let mut sorted = durations.to_vec();
		sorted.sort_unstable();

		let sum: u64 = durations.iter().sum();
		let mean = sum / count as u64;

		let median = if count.is_multiple_of(2) {
			(sorted[count / 2 - 1] + sorted[count / 2]) / 2
		} else {
			sorted[count / 2]
		};

		// The percentile index uses integer math. `p_fixed` is the percentile
		// scaled by 10000 (9500 for 95%), and the index is
		// (p_fixed * (count - 1) + 5000) / 10000.
		let percentile_value = |p_fixed: u32| -> u64 {
			let count_minus_one = (count - 1) as u128;
			let p_fixed_u128 = p_fixed as u128;
			// The product runs in u128, so the multiplication cannot overflow.
			let index = ((p_fixed_u128 * count_minus_one + 5000) / 10000) as usize;
			sorted[index.min(count - 1)]
		};

		// The percentiles are a `Vec` of pairs for ASN.1 compatibility.
		let percentiles = vec![
			PercentileValue { percentile: Percentile::P50, value: median },
			PercentileValue {
				percentile: Percentile::P90,
				value: percentile_value(Percentile::P90.as_fixed_point()),
			},
			PercentileValue {
				percentile: Percentile::P95,
				value: percentile_value(Percentile::P95.as_fixed_point()),
			},
			PercentileValue {
				percentile: Percentile::P99,
				value: percentile_value(Percentile::P99.as_fixed_point()),
			},
			PercentileValue {
				percentile: Percentile::P99_9,
				value: percentile_value(Percentile::P99_9.as_fixed_point()),
			},
			PercentileValue {
				percentile: Percentile::P99_99,
				value: percentile_value(Percentile::P99_99.as_fixed_point()),
			},
		];

		// A sample of 30 or more gets a simple confidence interval
		// approximation.
		let confidence_intervals = if count >= 30 {
			// The interval uses the standard error approximation.
			let variance: u64 = durations
				.iter()
				.map(|&x| {
					let diff = x.abs_diff(mean);
					diff.saturating_mul(diff)
				})
				.sum::<u64>()
				/ count as u64;

			// The standard deviation is the integer square root of the
			// variance.
			let std_dev = variance.isqrt();

			// The 95% confidence margin is (1.96 * std_dev) / sqrt(count),
			// which integer math computes as
			// (std_dev * 196) / (100 * sqrt(count)).
			let count_sqrt = count.isqrt() as u64;
			// std_dev * 196 can overflow u64, so the product runs in u128.
			let margin = ((std_dev as u128 * 196) / (100 * count_sqrt.max(1) as u128)) as u64;

			Some(ConfidenceIntervals {
				level: 9500, // 0.95 * 10000
				lower: mean.saturating_sub(margin),
				upper: mean.saturating_add(margin),
			})
		} else {
			None
		};

		Ok(StatisticalMeasures {
			count: count as u64,
			mean,
			median,
			percentiles,
			confidence_intervals,
			custom: Vec::new(),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_percentile_as_float() {
		assert_eq!(Percentile::P50.as_float(), 0.50);
		assert_eq!(Percentile::P90.as_float(), 0.90);
		assert_eq!(Percentile::P95.as_float(), 0.95);
		assert_eq!(Percentile::P99.as_float(), 0.99);
		assert_eq!(Percentile::P99_9.as_float(), 0.999);
		assert_eq!(Percentile::P99_99.as_float(), 0.9999);
	}

	#[test]
	fn test_percentile_as_fixed_point() {
		assert_eq!(Percentile::P50.as_fixed_point(), 5000);
		assert_eq!(Percentile::P90.as_fixed_point(), 9000);
		assert_eq!(Percentile::P95.as_fixed_point(), 9500);
		assert_eq!(Percentile::P99.as_fixed_point(), 9900);
		assert_eq!(Percentile::P99_9.as_fixed_point(), 9990);
		assert_eq!(Percentile::P99_99.as_fixed_point(), 9999);
	}

	#[test]
	fn test_basic_analyzer_empty() {
		let analyzer = DefaultStatisticalAnalyzer;
		let result = analyzer.analyze(&[]);
		assert!(matches!(result, Err(TightBeamError::InvalidMetadata)));
	}

	#[test]
	fn test_basic_analyzer_single_value() -> Result<(), Box<dyn core::error::Error>> {
		let analyzer = DefaultStatisticalAnalyzer;
		let durations = vec![100_000_000]; // 100ms

		let result = analyzer.analyze(&durations)?;
		assert_eq!(result.count, 1);
		assert_eq!(result.mean, 100_000_000);
		assert_eq!(result.median, 100_000_000);
		assert_eq!(
			result
				.percentiles
				.iter()
				.find(|pv| pv.percentile == Percentile::P50)
				.map(|pv| pv.value),
			Some(100_000_000)
		);

		Ok(())
	}

	#[test]
	fn test_basic_analyzer_multiple_values() -> Result<(), Box<dyn core::error::Error>> {
		let analyzer = DefaultStatisticalAnalyzer;
		// The durations are 10ms, 20ms, 30ms, 40ms, and 50ms.
		let durations = vec![10_000_000, 20_000_000, 30_000_000, 40_000_000, 50_000_000];

		let result = analyzer.analyze(&durations)?;
		assert_eq!(result.count, 5);
		assert_eq!(result.mean, 30_000_000);
		assert_eq!(result.median, 30_000_000); // P50
		assert_eq!(
			result
				.percentiles
				.iter()
				.find(|pv| pv.percentile == Percentile::P50)
				.map(|pv| pv.value),
			Some(30_000_000)
		);
		assert_eq!(
			result
				.percentiles
				.iter()
				.find(|pv| pv.percentile == Percentile::P95)
				.map(|pv| pv.value),
			Some(50_000_000)
		);

		Ok(())
	}

	#[test]
	fn test_basic_analyzer_confidence_intervals() -> Result<(), Box<dyn core::error::Error>> {
		let analyzer = DefaultStatisticalAnalyzer;
		// A confidence interval needs 30 or more values, so the test uses 50.
		let durations: Vec<u64> = (1..=50).map(|i| i * 1_000_000).collect();

		let result = analyzer.analyze(&durations)?;
		let Some(ci) = result.confidence_intervals else {
			return Err(crate::testing::error::TestingError::InvariantViolated.into());
		};
		assert_eq!(ci.level, 9500);
		assert!(ci.lower < ci.upper);
		assert!(ci.lower <= result.mean);
		assert!(ci.upper >= result.mean);

		Ok(())
	}

	#[test]
	fn test_basic_analyzer_percentiles() -> Result<(), Box<dyn core::error::Error>> {
		let analyzer = DefaultStatisticalAnalyzer;
		// The input holds 100 values from 1ms to 100ms.
		let durations: Vec<u64> = (1..=100).map(|i| i * 1_000_000).collect();

		// Every percentile level is present.
		let result = analyzer.analyze(&durations)?;
		assert!(result.percentiles.iter().any(|pv| pv.percentile == Percentile::P50));
		assert!(result.percentiles.iter().any(|pv| pv.percentile == Percentile::P90));
		assert!(result.percentiles.iter().any(|pv| pv.percentile == Percentile::P95));
		assert!(result.percentiles.iter().any(|pv| pv.percentile == Percentile::P99));
		assert!(result.percentiles.iter().any(|pv| pv.percentile == Percentile::P99_9));
		assert!(result.percentiles.iter().any(|pv| pv.percentile == Percentile::P99_99));

		// The percentiles are monotonic: P50 <= P90 <= P95 <= P99 <= P99.9 <=
		// P99.99.
		let p50 = result
			.percentiles
			.iter()
			.find(|pv| pv.percentile == Percentile::P50)
			.ok_or(crate::testing::error::TestingError::InvariantViolated)?
			.value;
		let p90 = result
			.percentiles
			.iter()
			.find(|pv| pv.percentile == Percentile::P90)
			.ok_or(crate::testing::error::TestingError::InvariantViolated)?
			.value;
		let p95 = result
			.percentiles
			.iter()
			.find(|pv| pv.percentile == Percentile::P95)
			.ok_or(crate::testing::error::TestingError::InvariantViolated)?
			.value;
		let p99 = result
			.percentiles
			.iter()
			.find(|pv| pv.percentile == Percentile::P99)
			.ok_or(crate::testing::error::TestingError::InvariantViolated)?
			.value;
		let p99_9 = result
			.percentiles
			.iter()
			.find(|pv| pv.percentile == Percentile::P99_9)
			.ok_or(crate::testing::error::TestingError::InvariantViolated)?
			.value;
		let p99_99 = result
			.percentiles
			.iter()
			.find(|pv| pv.percentile == Percentile::P99_99)
			.ok_or(crate::testing::error::TestingError::InvariantViolated)?
			.value;

		assert!(p50 <= p90);
		assert!(p90 <= p95);
		assert!(p95 <= p99);
		assert!(p99 <= p99_9);
		assert!(p99_9 <= p99_99);

		Ok(())
	}
}
