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
	use crate::testing::TestResult;

	/// The percentile levels of the house analyzer, in the order it reports
	/// them.
	const LEVELS: [Percentile; 6] = [
		Percentile::P50,
		Percentile::P90,
		Percentile::P95,
		Percentile::P99,
		Percentile::P99_9,
		Percentile::P99_99,
	];

	/// The samples of 1 ms, 2 ms, and so on up to `count` ms, in nanoseconds.
	fn ascending_millis(count: u64) -> Vec<u64> {
		(1..=count).map(|millis| millis * 1_000_000).collect()
	}

	/// Each level of [`LEVELS`] with its value in `values`, in order.
	fn percentiles(values: [u64; 6]) -> Vec<PercentileValue> {
		let levels = LEVELS.into_iter().zip(values);
		let paired = levels.map(|(percentile, value)| PercentileValue { percentile, value });
		paired.collect()
	}

	/// The measures of `count` samples of mean `mean`, with the percentile
	/// values `values` and no confidence interval. The median is the value of
	/// P50.
	fn measures(count: u64, mean: u64, values: [u64; 6]) -> StatisticalMeasures {
		let [median, ..] = values;
		let percentiles = percentiles(values);
		StatisticalMeasures { count, mean, median, percentiles, confidence_intervals: None, custom: Vec::new() }
	}

	// Each percentile reads as its fraction and as its fixed-point integer
	// scaled by 10,000.
	crate::tb_cases! {
		fn a_percentile_reads_as_its_fraction_and_its_fixed_point(
			(percentile, fraction, fixed_point): (Percentile, f64, u32)
		) {
			let forms = (percentile.as_float(), percentile.as_fixed_point());
			assert_eq!(forms, (fraction, fixed_point));
		}

		cases {
			p50 => (Percentile::P50, 0.50, 5000),
			p90 => (Percentile::P90, 0.90, 9000),
			p95 => (Percentile::P95, 0.95, 9500),
			p99 => (Percentile::P99, 0.99, 9900),
			p99_9 => (Percentile::P99_9, 0.999, 9990),
			p99_99 => (Percentile::P99_99, 0.9999, 9999),
		}
	}

	/// The house analyzer refuses a sample set with no sample.
	#[test]
	fn the_analysis_refuses_an_empty_sample() {
		let analyzed = DefaultStatisticalAnalyzer.analyze(&[]);
		assert!(matches!(analyzed, Err(TightBeamError::InvalidMetadata)));
	}

	// A sample of fewer than 30 values has its count, its mean, its median,
	// and its percentiles, and no confidence interval. The rank of each
	// percentile rounds to the nearest index.
	crate::tb_cases! {
		fn the_measures_of_a_small_sample((durations, measured): (&[u64], StatisticalMeasures)) -> TestResult {
			let analyzed = DefaultStatisticalAnalyzer.analyze(durations)?;
			assert_eq!(analyzed, measured);
			Ok(())
		}

		cases {
			one_value => (&[100_000_000], measures(1, 100_000_000, [100_000_000; 6])),
			/// P90 and each level above it round to the index of the largest
			/// sample, 50 ms.
			five_values => (
				&[10_000_000, 20_000_000, 30_000_000, 40_000_000, 50_000_000],
				measures(5, 30_000_000, [30_000_000, 50_000_000, 50_000_000, 50_000_000, 50_000_000, 50_000_000]),
			),
		}
	}

	/// A sample of 30 values or more has a 95% confidence interval of its
	/// mean. The 50 samples of 1 ms to 50 ms have a mean of 25.5 ms and a
	/// standard deviation of 14,430,869 ns, so the margin of 1.96 deviations
	/// over 7, the integer square root of 50, is 4,040,643 ns.
	#[test]
	fn a_sample_of_thirty_values_or_more_has_a_confidence_interval_of_its_mean() -> TestResult {
		let durations = ascending_millis(50);
		let analyzed = DefaultStatisticalAnalyzer.analyze(&durations)?;

		let interval = ConfidenceIntervals { level: 9500, lower: 21_459_357, upper: 29_540_643 };
		assert_eq!(analyzed.confidence_intervals, Some(interval));
		Ok(())
	}

	/// Each percentile of the 100 samples of 1 ms to 100 ms reads the sample
	/// at its rank, rounded to the nearest index. The median of an even count
	/// is the mean of its two middle samples.
	#[test]
	fn each_percentile_reads_the_sample_at_its_rank() -> TestResult {
		let durations = ascending_millis(100);
		let analyzed = DefaultStatisticalAnalyzer.analyze(&durations)?;

		let values = [50_500_000, 90_000_000, 95_000_000, 99_000_000, 100_000_000, 100_000_000];
		assert_eq!(analyzed.percentiles, percentiles(values));
		Ok(())
	}
}
