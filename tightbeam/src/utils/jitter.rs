//! Jitter calculation utilities
//!
//! Provides traits and implementations for calculating jitter from observed durations.
//! Used by both timing verification and restart policies.

use crate::TightBeamError;

/// Trait for calculating jitter from a collection of observed durations.
///
/// Jitter represents the variation in execution times. Different calculation
/// methods provide different statistical measures of this variation.
pub trait JitterCalculator: Send + Sync + core::fmt::Debug {
	/// Calculate jitter from observed durations.
	///
	/// # Arguments
	/// * `durations` - Slice of observed durations in nanoseconds
	///
	/// # Returns
	/// * `Ok(u64)` - Calculated jitter in nanoseconds
	/// * `Err(TightBeamError)` - If calculation fails (e.g., insufficient data)
	///
	/// # Errors
	/// Returns an error if:
	/// * `durations` is empty
	/// * `durations` has fewer than 2 elements (for methods requiring multiple samples)
	fn calculate(&self, durations: &[u64]) -> Result<u64, TightBeamError>;
}

/// Min-Max jitter calculator (default).
///
/// Calculates jitter as the difference between maximum and minimum observed durations.
/// This is the simplest and most commonly used jitter metric.
#[derive(Default, Debug, Clone, Copy)]
pub struct MinMaxJitter;

impl JitterCalculator for MinMaxJitter {
	fn calculate(&self, durations: &[u64]) -> Result<u64, TightBeamError> {
		if durations.is_empty() {
			return Err(TightBeamError::InvalidMetadata);
		}

		if durations.len() < 2 {
			return Ok(0);
		}

		let min = durations.iter().min().copied().unwrap_or(0);
		let max = durations.iter().max().copied().unwrap_or(0);
		Ok(max.saturating_sub(min))
	}
}

/// Variance-based jitter calculator.
///
/// Calculates jitter as the variance of observed durations.
/// Variance measures the spread of data points around the mean.
#[derive(Default, Debug, Clone, Copy)]
pub struct VarianceJitter;

impl JitterCalculator for VarianceJitter {
	fn calculate(&self, durations: &[u64]) -> Result<u64, TightBeamError> {
		if durations.is_empty() {
			return Err(TightBeamError::InvalidMetadata);
		}

		if durations.len() < 2 {
			return Ok(0);
		}

		// Calculate mean
		let sum: u64 = durations.iter().sum();
		let count = durations.len() as u64;
		let mean = sum / count;

		// Calculate variance: sum of squared differences from mean
		let variance_sum: u128 = durations
			.iter()
			.map(|&d| {
				let diff = if d > mean {
					d - mean
				} else {
					mean - d
				};
				(diff as u128).saturating_pow(2)
			})
			.sum();

		// Return variance (average of squared differences)
		let variance = (variance_sum / count as u128) as u64;
		Ok(variance)
	}
}

/// Standard deviation-based jitter calculator.
///
/// Calculates jitter as the standard deviation of observed durations.
/// Standard deviation is the square root of variance, providing a measure
/// in the same units as the original data.
#[derive(Default, Debug, Clone, Copy)]
pub struct StdDevJitter;

impl JitterCalculator for StdDevJitter {
	fn calculate(&self, durations: &[u64]) -> Result<u64, TightBeamError> {
		if durations.is_empty() {
			return Err(TightBeamError::InvalidMetadata);
		}

		if durations.len() < 2 {
			return Ok(0);
		}

		// Calculate mean
		let sum: u64 = durations.iter().sum();
		let count = durations.len() as u64;
		let mean = sum / count;

		// Calculate variance: sum of squared differences from mean
		let variance_sum: u128 = durations
			.iter()
			.map(|&d| {
				let diff = if d > mean {
					d - mean
				} else {
					mean - d
				};
				(diff as u128).saturating_pow(2)
			})
			.sum();

		// Calculate variance (average of squared differences)
		let variance = variance_sum / count as u128;

		// Calculate standard deviation: square root of variance
		// Use integer square root approximation
		let std_dev = integer_sqrt(variance);
		Ok(std_dev as u64)
	}
}

/// Decorrelated jitter calculator.
///
/// Calculates jitter using the decorrelated jitter algorithm.
/// Uses max duration as base, calculates range from max/3 to max,
/// and returns the range as the jitter value.
///
/// This is adapted from the decorrelated jitter algorithm used in
/// restart policies (see `transport/policy.rs::DecorrelatedJitter`).
#[derive(Default, Debug, Clone, Copy)]
pub struct DecorrelatedJitterCalculator;

impl JitterCalculator for DecorrelatedJitterCalculator {
	fn calculate(&self, durations: &[u64]) -> Result<u64, TightBeamError> {
		if durations.is_empty() {
			return Err(TightBeamError::InvalidMetadata);
		}

		if durations.len() < 2 {
			return Ok(0);
		}

		let max_duration = durations.iter().max().copied().unwrap_or(0);
		if max_duration == 0 {
			return Ok(0);
		}

		// Decorrelated jitter: range from max/3 to max
		let min = max_duration / 3;
		let range = max_duration.saturating_sub(min);
		Ok(range)
	}
}

/// Integer square root approximation using Newton's method.
///
/// Returns the largest integer n such that n² ≤ value.
fn integer_sqrt(value: u128) -> u128 {
	if value == 0 {
		return 0;
	}
	if value == 1 {
		return 1;
	}

	// Initial guess: value / 2
	let mut x = value / 2;
	let mut prev = 0;

	// Newton's method: x_{n+1} = (x_n + value/x_n) / 2
	while x != prev {
		prev = x;
		x = (x + value / x) / 2;
	}

	x
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_min_max_jitter() {
		let calculator = MinMaxJitter;
		assert!(matches!(calculator.calculate(&[]), Err(TightBeamError::InvalidMetadata)));
		assert_eq!(calculator.calculate(&[100]).unwrap(), 0);
		assert_eq!(calculator.calculate(&[100, 200]).unwrap(), 100);
		assert_eq!(calculator.calculate(&[50, 100, 150, 200]).unwrap(), 150);
	}

	#[test]
	fn test_variance_jitter() {
		let calculator = VarianceJitter;
		assert!(matches!(calculator.calculate(&[]), Err(TightBeamError::InvalidMetadata)));
		assert_eq!(calculator.calculate(&[100]).unwrap(), 0);

		// Test with known values: [100, 200]
		// Mean = 150, variance = ((100-150)² + (200-150)²) / 2 = (2500 + 2500) / 2 = 2500
		let result = calculator.calculate(&[100, 200]).unwrap();
		assert_eq!(result, 2500);
	}

	#[test]
	fn test_std_dev_jitter() {
		let calculator = StdDevJitter;
		assert!(matches!(calculator.calculate(&[]), Err(TightBeamError::InvalidMetadata)));
		assert_eq!(calculator.calculate(&[100]).unwrap(), 0);

		// Test with known values: [100, 200]
		// Variance = 2500, std_dev = sqrt(2500) = 50
		let result = calculator.calculate(&[100, 200]).unwrap();
		assert_eq!(result, 50);
	}

	#[test]
	fn test_decorrelated_jitter() {
		let calculator = DecorrelatedJitterCalculator;
		assert!(matches!(calculator.calculate(&[]), Err(TightBeamError::InvalidMetadata)));
		assert_eq!(calculator.calculate(&[100]).unwrap(), 0);

		// Test with max = 300: range = 300 - (300/3) = 300 - 100 = 200
		assert_eq!(calculator.calculate(&[100, 200, 300]).unwrap(), 200);

		// Test with max = 150: range = 150 - (150/3) = 150 - 50 = 100
		assert_eq!(calculator.calculate(&[50, 100, 150]).unwrap(), 100);
	}

	#[test]
	fn test_integer_sqrt() {
		assert_eq!(integer_sqrt(0), 0);
		assert_eq!(integer_sqrt(1), 1);
		assert_eq!(integer_sqrt(4), 2);
		assert_eq!(integer_sqrt(9), 3);
		assert_eq!(integer_sqrt(16), 4);
		assert_eq!(integer_sqrt(25), 5);
		assert_eq!(integer_sqrt(2500), 50);
	}
}
