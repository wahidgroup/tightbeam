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
	use crate::testing::TestResult;

	// Each calculator measures the jitter of the samples of its row, and one
	// sample has no jitter.
	crate::tb_cases! {
		fn a_calculator_measures_the_jitter_of_its_samples(
			(calculator, samples, jitter): (&dyn JitterCalculator, &[u64], u64)
		) -> TestResult {
			let measured = calculator.calculate(samples)?;
			assert_eq!(measured, jitter);
			Ok(())
		}

		cases {
			min_max_of_one_sample => (&MinMaxJitter, &[100], 0),
			min_max_of_two_samples => (&MinMaxJitter, &[100, 200], 100),
			min_max_of_four_samples => (&MinMaxJitter, &[50, 100, 150, 200], 150),
			variance_of_one_sample => (&VarianceJitter, &[100], 0),
			/// The mean of 100 and 200 is 150, so the variance is
			/// ((100 - 150)² + (200 - 150)²) / 2 = 2500.
			variance_of_two_samples => (&VarianceJitter, &[100, 200], 2500),
			std_dev_of_one_sample => (&StdDevJitter, &[100], 0),
			/// The variance of 100 and 200 is 2500, so the standard deviation
			/// is 50.
			std_dev_of_two_samples => (&StdDevJitter, &[100, 200], 50),
			decorrelated_of_one_sample => (&DecorrelatedJitterCalculator, &[100], 0),
			/// The largest sample, 300, sets the window from 300 / 3 to 300,
			/// which is 200 wide.
			decorrelated_up_to_300 => (&DecorrelatedJitterCalculator, &[100, 200, 300], 200),
			/// The largest sample, 150, sets the window from 150 / 3 to 150,
			/// which is 100 wide.
			decorrelated_up_to_150 => (&DecorrelatedJitterCalculator, &[50, 100, 150], 100),
		}
	}

	// Each calculator refuses a sample set with no sample.
	crate::tb_cases! {
		fn a_calculator_refuses_an_empty_sample(calculator: &dyn JitterCalculator) {
			let measured = calculator.calculate(&[]);
			assert!(matches!(measured, Err(TightBeamError::InvalidMetadata)));
		}

		cases {
			min_max => &MinMaxJitter,
			variance => &VarianceJitter,
			std_dev => &StdDevJitter,
			decorrelated => &DecorrelatedJitterCalculator,
		}
	}
}
