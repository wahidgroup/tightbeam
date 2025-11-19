//! Statistical analysis utilities
//!
//! Provides traits and implementations for statistical analysis of timing data.
//! Used for percentile-based WCET analysis and other statistical measures.

use crate::der::{Enumerated, Sequence};
use crate::error::TightBeamError;
use crate::utils::math::integer_sqrt;

/// Trait for statistical analysis of timing data.
///
/// Allows plugging in custom statistical models without modifying core
/// verification logic. Similar to `JitterCalculator` pattern.
pub trait StatisticalAnalyzer: Send + Sync + core::fmt::Debug {
	/// Analyze a collection of observed durations.
	///
	/// Returns statistical measures (percentiles, confidence intervals, etc.)
	///
	/// # Arguments
	/// * `durations` - Slice of observed durations in nanoseconds
	///
	/// # Returns
	/// * `Ok(StatisticalMeasures)` - Statistical measures from analysis
	/// * `Err(TightBeamError)` - If analysis fails (e.g., insufficient data)
	///
	/// # Errors
	/// Returns an error if:
	/// * `durations` is empty
	/// * Analysis requires more samples than available
	fn analyze(&self, durations: &[u64]) -> Result<StatisticalMeasures, TightBeamError>;
}

/// Percentile levels for statistical analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Enumerated)]
#[repr(u8)]
pub enum Percentile {
	/// 50th percentile (median)
	P50 = 0,
	/// 90th percentile
	P90 = 1,
	/// 95th percentile
	P95 = 2,
	/// 99th percentile
	P99 = 3,
	/// 99.9th percentile
	P99_9 = 4,
	/// 99.99th percentile
	P99_99 = 5,
}

impl Percentile {
	/// Get the percentile value as a float (0.0 to 1.0).
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

	/// Get percentile as fixed-point integer (multiplied by 10000).
	/// Example: P95 -> 9500, P99.9 -> 9990
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
pub struct ConfidenceIntervals {
	/// Confidence level (e.g., 9500 for 95% - stored as integer * 10000)
	pub level: u32,
	/// Lower bound (nanoseconds)
	pub lower: u64,
	/// Upper bound (nanoseconds)
	pub upper: u64,
}

/// Key-value pair for percentile data (ASN.1-compatible)
#[derive(Debug, Clone, Sequence, PartialEq)]
pub struct PercentileValue {
	pub percentile: Percentile,
	pub value: u64,
}

/// Key-value pair for custom metrics (ASN.1-compatible)
#[derive(Debug, Clone, Sequence, PartialEq)]
pub struct CustomMetric {
	pub key: String,
	/// Value stored as integer * 10000 (fixed-point representation)
	pub value: i64,
}

/// Statistical measures from analysis.
#[derive(Debug, Clone, Sequence, PartialEq)]
pub struct StatisticalMeasures {
	/// Sample count
	pub count: u64,
	/// Mean (average) in nanoseconds
	pub mean: u64,
	/// Median (50th percentile) in nanoseconds
	pub median: u64,
	/// Percentiles (P95, P99, P99.9, etc.) in nanoseconds
	pub percentiles: Vec<PercentileValue>,
	/// Confidence intervals (optional)
	#[asn1(optional = "true")]
	pub confidence_intervals: Option<ConfidenceIntervals>,
	/// Additional custom metrics (extensible)
	pub custom: Vec<CustomMetric>,
}

/// Basic statistical analyzer (default implementation).
///
/// Provides:
/// - Percentiles (P50, P90, P95, P99, P99.9)
/// - Mean, median
/// - Simple confidence intervals (if sample size sufficient)
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

		// Calculate mean
		let sum: u64 = durations.iter().sum();
		let mean = sum / count as u64;

		// Calculate median (P50)
		let median = if count % 2 == 0 {
			(sorted[count / 2 - 1] + sorted[count / 2]) / 2
		} else {
			sorted[count / 2]
		};

		// Helper to calculate percentile value using integer math
		// p_fixed is percentile * 10000 (e.g., 9500 for 95%)
		// Formula: index = (p_fixed * (count - 1) + 5000) / 10000
		let percentile_value = |p_fixed: u32| -> u64 {
			let count_minus_one = (count - 1) as u128;
			let p_fixed_u128 = p_fixed as u128;
			// Calculate: (p_fixed * (count - 1) + 5000) / 10000
			// Use u128 to avoid overflow in multiplication
			let index = ((p_fixed_u128 * count_minus_one + 5000) / 10000) as usize;
			sorted[index.min(count - 1)]
		};

		// Calculate percentiles as Vec for ASN.1 compatibility
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

		// Calculate confidence intervals (simple approximation for large samples)
		let confidence_intervals = if count >= 30 {
			// Use standard error approximation
			let variance: u64 = durations
				.iter()
				.map(|&x| {
					let diff = x.abs_diff(mean);
					diff.saturating_mul(diff)
				})
				.sum::<u64>()
				/ count as u64;

			// Calculate standard deviation using integer square root
			// Use u128 to avoid overflow in intermediate calculations
			let std_dev = integer_sqrt(variance as u128) as u64;

			// 95% confidence interval margin: (1.96 * std_dev) / sqrt(count)
			// Using integer math: (std_dev * 196) / (100 * sqrt(count))
			// Use u128 for intermediate to avoid overflow
			let count_sqrt = integer_sqrt(count as u128) as u64;
			// std_dev * 196 could overflow u64, so use u128
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
	fn test_basic_analyzer_single_value() {
		let analyzer = DefaultStatisticalAnalyzer;
		let durations = vec![100_000_000]; // 100ms

		let result = analyzer.analyze(&durations).unwrap();
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
	}

	#[test]
	fn test_basic_analyzer_multiple_values() {
		let analyzer = DefaultStatisticalAnalyzer;
		// Durations: 10ms, 20ms, 30ms, 40ms, 50ms
		let durations = vec![10_000_000, 20_000_000, 30_000_000, 40_000_000, 50_000_000];

		let result = analyzer.analyze(&durations).unwrap();
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
	}

	#[test]
	fn test_basic_analyzer_confidence_intervals() {
		let analyzer = DefaultStatisticalAnalyzer;
		// Generate 30+ values for confidence interval calculation
		let durations: Vec<u64> = (1..=50).map(|i| i * 1_000_000).collect();

		let result = analyzer.analyze(&durations).unwrap();
		assert!(result.confidence_intervals.is_some());

		let ci = result.confidence_intervals.unwrap();
		assert_eq!(ci.level, 9500);
		assert!(ci.lower < ci.upper);
		assert!(ci.lower <= result.mean);
		assert!(ci.upper >= result.mean);
	}

	#[test]
	fn test_basic_analyzer_percentiles() {
		let analyzer = DefaultStatisticalAnalyzer;
		// 100 values from 1ms to 100ms
		let durations: Vec<u64> = (1..=100).map(|i| i * 1_000_000).collect();

		// Check all percentiles are present
		let result = analyzer.analyze(&durations).unwrap();
		assert!(result.percentiles.iter().any(|pv| pv.percentile == Percentile::P50));
		assert!(result.percentiles.iter().any(|pv| pv.percentile == Percentile::P90));
		assert!(result.percentiles.iter().any(|pv| pv.percentile == Percentile::P95));
		assert!(result.percentiles.iter().any(|pv| pv.percentile == Percentile::P99));
		assert!(result.percentiles.iter().any(|pv| pv.percentile == Percentile::P99_9));
		assert!(result.percentiles.iter().any(|pv| pv.percentile == Percentile::P99_99));

		// Percentiles should be monotonic (P50 <= P90 <= P95 <= P99 <= P99.9 <= P99.99)
		let p50 = result
			.percentiles
			.iter()
			.find(|pv| pv.percentile == Percentile::P50)
			.unwrap()
			.value;
		let p90 = result
			.percentiles
			.iter()
			.find(|pv| pv.percentile == Percentile::P90)
			.unwrap()
			.value;
		let p95 = result
			.percentiles
			.iter()
			.find(|pv| pv.percentile == Percentile::P95)
			.unwrap()
			.value;
		let p99 = result
			.percentiles
			.iter()
			.find(|pv| pv.percentile == Percentile::P99)
			.unwrap()
			.value;
		let p99_9 = result
			.percentiles
			.iter()
			.find(|pv| pv.percentile == Percentile::P99_9)
			.unwrap()
			.value;
		let p99_99 = result
			.percentiles
			.iter()
			.find(|pv| pv.percentile == Percentile::P99_99)
			.unwrap()
			.value;

		assert!(p50 <= p90);
		assert!(p90 <= p95);
		assert!(p95 <= p99);
		assert!(p99 <= p99_9);
		assert!(p99_9 <= p99_99);
	}
}
