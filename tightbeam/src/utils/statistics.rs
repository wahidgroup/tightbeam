//! Statistical analysis utilities
//!
//! Provides traits and implementations for statistical analysis of timing data.
//! Used for percentile-based WCET analysis and other statistical measures.

use std::collections::HashMap;

use crate::error::TightBeamError;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Percentile {
	/// 50th percentile (median)
	P50,
	/// 90th percentile
	P90,
	/// 95th percentile
	P95,
	/// 99th percentile
	P99,
	/// 99.9th percentile
	P99_9,
	/// 99.99th percentile
	P99_99,
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
}

/// Confidence intervals for statistical measures.
#[derive(Debug, Clone)]
pub struct ConfidenceIntervals {
	/// Confidence level (e.g., 0.95 for 95%)
	pub level: f64,
	/// Lower bound (nanoseconds)
	pub lower: u64,
	/// Upper bound (nanoseconds)
	pub upper: u64,
}

/// Statistical measures from analysis.
#[derive(Debug, Clone)]
pub struct StatisticalMeasures {
	/// Sample count
	pub count: usize,
	/// Mean (average) in nanoseconds
	pub mean: u64,
	/// Median (50th percentile) in nanoseconds
	pub median: u64,
	/// Percentiles (P95, P99, P99.9, etc.) in nanoseconds
	pub percentiles: HashMap<Percentile, u64>,
	/// Confidence intervals (optional)
	pub confidence_intervals: Option<ConfidenceIntervals>,
	/// Additional custom metrics (extensible)
	pub custom: HashMap<String, f64>,
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

		// Calculate percentiles
		let mut percentiles = HashMap::new();
		percentiles.insert(Percentile::P50, median);

		// Helper to calculate percentile value
		let percentile_value = |p: f64| -> u64 {
			let index = (p * (count - 1) as f64).round() as usize;
			sorted[index.min(count - 1)]
		};

		percentiles.insert(Percentile::P90, percentile_value(0.90));
		percentiles.insert(Percentile::P95, percentile_value(0.95));
		percentiles.insert(Percentile::P99, percentile_value(0.99));
		percentiles.insert(Percentile::P99_9, percentile_value(0.999));
		percentiles.insert(Percentile::P99_99, percentile_value(0.9999));

		// Calculate confidence intervals (simple approximation for large samples)
		let confidence_intervals = if count >= 30 {
			// Use standard error approximation
			let variance: u64 = durations
				.iter()
				.map(|&x| {
					let diff = if x > mean {
						x - mean
					} else {
						mean - x
					};
					diff.saturating_mul(diff)
				})
				.sum::<u64>()
				/ count as u64;
			let std_dev = (variance as f64).sqrt() as u64;

			// 95% confidence interval (1.96 * std_error, simplified)
			let margin = (std_dev as f64 * 1.96 / (count as f64).sqrt()) as u64;
			Some(ConfidenceIntervals {
				level: 0.95,
				lower: mean.saturating_sub(margin),
				upper: mean.saturating_add(margin),
			})
		} else {
			None
		};

		Ok(StatisticalMeasures { count, mean, median, percentiles, confidence_intervals, custom: HashMap::new() })
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
		assert_eq!(result.percentiles.get(&Percentile::P50), Some(&100_000_000));
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
		assert_eq!(result.percentiles.get(&Percentile::P50), Some(&30_000_000));
		assert_eq!(result.percentiles.get(&Percentile::P95), Some(&50_000_000));
	}

	#[test]
	fn test_basic_analyzer_confidence_intervals() {
		let analyzer = DefaultStatisticalAnalyzer;
		// Generate 30+ values for confidence interval calculation
		let durations: Vec<u64> = (1..=50).map(|i| i * 1_000_000).collect();
		let result = analyzer.analyze(&durations).unwrap();

		assert!(result.confidence_intervals.is_some());
		let ci = result.confidence_intervals.unwrap();
		assert_eq!(ci.level, 0.95);
		assert!(ci.lower < ci.upper);
		assert!(ci.lower <= result.mean);
		assert!(ci.upper >= result.mean);
	}

	#[test]
	fn test_basic_analyzer_percentiles() {
		let analyzer = DefaultStatisticalAnalyzer;
		// 100 values from 1ms to 100ms
		let durations: Vec<u64> = (1..=100).map(|i| i * 1_000_000).collect();
		let result = analyzer.analyze(&durations).unwrap();

		// Check all percentiles are present
		assert!(result.percentiles.contains_key(&Percentile::P50));
		assert!(result.percentiles.contains_key(&Percentile::P90));
		assert!(result.percentiles.contains_key(&Percentile::P95));
		assert!(result.percentiles.contains_key(&Percentile::P99));
		assert!(result.percentiles.contains_key(&Percentile::P99_9));
		assert!(result.percentiles.contains_key(&Percentile::P99_99));

		// Percentiles should be monotonic (P50 <= P90 <= P95 <= P99 <= P99.9 <= P99.99)
		let p50 = result.percentiles.get(&Percentile::P50).unwrap();
		let p90 = result.percentiles.get(&Percentile::P90).unwrap();
		let p95 = result.percentiles.get(&Percentile::P95).unwrap();
		let p99 = result.percentiles.get(&Percentile::P99).unwrap();
		let p99_9 = result.percentiles.get(&Percentile::P99_9).unwrap();
		let p99_99 = result.percentiles.get(&Percentile::P99_99).unwrap();

		assert!(*p50 <= *p90);
		assert!(*p90 <= *p95);
		assert!(*p95 <= *p99);
		assert!(*p99 <= *p99_9);
		assert!(*p99_9 <= *p99_99);
	}
}
