//! Jitter calculation for timing verification.
//!
//! `JitterCalculator` turns observed durations into one jitter value, and this
//! module holds four calculators of it.

use crate::transport::policy::decorrelated_bounds;
use crate::TightBeamError;

/// A method that calculates jitter from a collection of observed durations.
///
/// Jitter is the variation in execution times, and each method measures that
/// variation with a different statistic.
pub trait JitterCalculator: Send + Sync + core::fmt::Debug {
	/// Calculates jitter from observed durations.
	///
	/// # Arguments
	/// * `durations` - The observed durations, in nanoseconds.
	///
	/// # Returns
	/// * `Ok(u64)` - The jitter, in nanoseconds.
	/// * `Err(TightBeamError)` - The calculation failed, for example on too little data.
	///
	/// # Errors
	/// Returns an error if:
	/// * `durations` is empty.
	/// * `durations` holds fewer samples than the calculator needs. The
	///   calculators of this module return 0 for a single sample.
	fn calculate(&self, durations: &[u64]) -> Result<u64, TightBeamError>;
}

/// The min-max jitter calculator, which timing verification uses by default.
///
/// The jitter is the difference between the largest and the smallest observed
/// duration, which is the simplest jitter metric.
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

/// The variance jitter calculator.
///
/// The jitter is the variance of the observed durations, which measures their
/// spread around the mean.
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

		let sum: u64 = durations.iter().sum();
		let count = durations.len() as u64;
		let mean = sum / count;

		// The variance sums the squared differences from the mean.
		let variance_sum: u128 = durations
			.iter()
			.map(|&d| {
				let diff = d.abs_diff(mean);
				(diff as u128).saturating_pow(2)
			})
			.sum();

		// The variance is the average of the squared differences.
		let variance = (variance_sum / count as u128) as u64;
		Ok(variance)
	}
}

/// The standard deviation jitter calculator.
///
/// The jitter is the standard deviation of the observed durations. It is the
/// square root of the variance, so it has the same unit as the durations.
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

		let sum: u64 = durations.iter().sum();
		let count = durations.len() as u64;
		let mean = sum / count;

		// The variance sums the squared differences from the mean.
		let variance_sum: u128 = durations
			.iter()
			.map(|&d| {
				let diff = d.abs_diff(mean);
				(diff as u128).saturating_pow(2)
			})
			.sum();

		// The variance is the average of the squared differences.
		let variance = variance_sum / count as u128;

		// The standard deviation is the integer square root of the variance.
		let std_dev = variance.isqrt();
		Ok(std_dev as u64)
	}
}

/// The decorrelated jitter calculator.
///
/// The jitter is the width of the decorrelated window that the largest
/// duration sets as its base, from max/3 to max.
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

		let (_, range) = decorrelated_bounds(max_duration);
		Ok(range)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_min_max_jitter() -> Result<(), Box<dyn core::error::Error>> {
		let calculator = MinMaxJitter;
		assert!(matches!(calculator.calculate(&[]), Err(TightBeamError::InvalidMetadata)));
		assert_eq!(calculator.calculate(&[100])?, 0);
		assert_eq!(calculator.calculate(&[100, 200])?, 100);
		assert_eq!(calculator.calculate(&[50, 100, 150, 200])?, 150);

		Ok(())
	}

	#[test]
	fn test_variance_jitter() -> Result<(), Box<dyn core::error::Error>> {
		let calculator = VarianceJitter;
		assert!(matches!(calculator.calculate(&[]), Err(TightBeamError::InvalidMetadata)));
		assert_eq!(calculator.calculate(&[100])?, 0);

		// For [100, 200], the mean is 150 and the variance is
		// ((100-150)² + (200-150)²) / 2
		// = (2500 + 2500) / 2 = 2500.
		let result = calculator.calculate(&[100, 200])?;
		assert_eq!(result, 2500);

		Ok(())
	}

	#[test]
	fn test_std_dev_jitter() -> Result<(), Box<dyn core::error::Error>> {
		let calculator = StdDevJitter;
		assert!(matches!(calculator.calculate(&[]), Err(TightBeamError::InvalidMetadata)));
		assert_eq!(calculator.calculate(&[100])?, 0);

		// For [100, 200], the variance is 2500 and
		// std_dev = sqrt(2500) = 50.
		let result = calculator.calculate(&[100, 200])?;
		assert_eq!(result, 50);

		Ok(())
	}

	#[test]
	fn test_decorrelated_jitter() -> Result<(), Box<dyn core::error::Error>> {
		let calculator = DecorrelatedJitterCalculator;
		assert!(matches!(calculator.calculate(&[]), Err(TightBeamError::InvalidMetadata)));
		assert_eq!(calculator.calculate(&[100])?, 0);

		// With max = 300, range = 300 - (300/3) = 300 - 100 = 200.
		assert_eq!(calculator.calculate(&[100, 200, 300])?, 200);

		// With max = 150, range = 150 - (150/3) = 150 - 50 = 100.
		assert_eq!(calculator.calculate(&[50, 100, 150])?, 100);

		Ok(())
	}
}
