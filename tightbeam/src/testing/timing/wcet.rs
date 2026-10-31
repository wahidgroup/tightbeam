//! The WCET (Worst-Case Execution Time) configuration and its builder.

use std::sync::Arc;
use std::time::Duration;

use super::constraints::same_instance;
use super::saturating_nanos;
use super::statistics::{DefaultStatisticalAnalyzer, Percentile, StatisticalAnalyzer};
use crate::builder::TypeBuilder;
use crate::testing::error::TestingError;
use crate::testing::specs::csp::Event;

/// A WCET bound on an event, with an optional percentile check.
///
/// # Examples
///
/// ```
/// use core::time::Duration;
///
/// use tightbeam::testing::timing::{Percentile, WcetConfig, WcetPercentile};
///
/// let percentile = WcetPercentile { percentile: Percentile::P99, analyzer: None };
/// let wcet = WcetConfig { duration: Duration::from_millis(10), percentile: Some(percentile) };
/// assert!(wcet.percentile.is_some());
/// ```
#[derive(Debug, Clone)]
pub struct WcetConfig {
	/// The longest duration that the bound allows.
	pub duration: Duration,
	/// The percentile check that the bound applies to, or `None` to bound
	/// the longest measured duration.
	pub percentile: Option<WcetPercentile>,
}

impl WcetConfig {
	/// The bound in nanoseconds, saturated at `u64::MAX`.
	pub(crate) fn bound_ns(&self) -> u64 {
		saturating_nanos(self.duration)
	}

	/// Whether this bound and `other` state one duration under one analysis.
	pub(crate) fn agrees_with(&self, other: &Self) -> bool {
		let same_percentile = match (&self.percentile, &other.percentile) {
			(Some(mine), Some(theirs)) => mine.agrees_with(theirs),
			(None, None) => true,
			_ => false,
		};

		self.duration == other.duration && same_percentile
	}

	/// The measure of the samples `durations` of `event`, in nanoseconds,
	/// that this bound tests: the percentile of a percentile check, or else
	/// the longest sample. An empty sample set measures as `None`.
	///
	/// # Errors
	///
	/// - The errors of [`WcetPercentile::measure`].
	pub(crate) fn measure(&self, event: Event, durations: &[u64]) -> Result<Option<u64>, TestingError> {
		let Some(longest) = durations.iter().max().copied() else {
			return Ok(None);
		};
		let Some(percentile) = &self.percentile else {
			return Ok(Some(longest));
		};

		percentile.measure(event, durations).map(Some)
	}
}

/// The percentile that a WCET bound applies to, with the analyzer that
/// computes it.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
///
/// use tightbeam::testing::timing::{DefaultStatisticalAnalyzer, Percentile, StatisticalAnalyzer, WcetPercentile};
///
/// let analyzer: Arc<dyn StatisticalAnalyzer> = Arc::new(DefaultStatisticalAnalyzer);
/// let percentile = WcetPercentile { percentile: Percentile::P95, analyzer: Some(analyzer) };
/// assert_eq!(percentile.percentile, Percentile::P95);
/// ```
#[derive(Debug, Clone)]
pub struct WcetPercentile {
	/// The percentile of the measured durations that the bound applies to.
	pub percentile: Percentile,
	/// The analyzer that computes the percentile, or `None` for
	/// [`DefaultStatisticalAnalyzer`].
	pub analyzer: Option<Arc<dyn StatisticalAnalyzer>>,
}

impl WcetPercentile {
	/// Whether this check and `other` test one percentile under one analyzer.
	///
	/// An analyzer is a trait object with no equality of its own, so two of
	/// them agree only when they are one instance.
	fn agrees_with(&self, other: &Self) -> bool {
		self.percentile == other.percentile && same_instance(&self.analyzer, &other.analyzer)
	}

	/// The percentile of the samples `durations` of `event`, in nanoseconds,
	/// under the analyzer of this check.
	///
	/// # Errors
	///
	/// - [`TestingError::WcetAnalysisFailed`] -- the analyzer fails on `durations`.
	/// - [`TestingError::WcetPercentileMissing`] -- the analyzer gives no value for the percentile.
	fn measure(&self, event: Event, durations: &[u64]) -> Result<u64, TestingError> {
		let percentile = self.percentile;
		let analyzer = self.analyzer.as_deref().unwrap_or(&DefaultStatisticalAnalyzer);
		let measures = analyzer.analyze(durations);
		let measures = measures.map_err(|cause| TestingError::WcetAnalysisFailed { event, cause: Box::new(cause) })?;

		let value = measures.percentiles.iter().find(|value| value.percentile == percentile);
		let value = value.ok_or(TestingError::WcetPercentileMissing { event, percentile })?;
		Ok(value.value)
	}
}

/// The builder of a [`WcetConfig`], whose build requires a duration, and a
/// percentile for an analyzer.
#[derive(Debug, Default, Clone)]
pub struct WcetConfigBuilder {
	duration: Option<Duration>,
	percentile: Option<Percentile>,
	analyzer: Option<Arc<dyn StatisticalAnalyzer>>,
}

impl WcetConfigBuilder {
	/// Sets the longest duration that the bound allows.
	pub fn with_duration(mut self, duration: Duration) -> Self {
		self.duration = Some(duration);
		self
	}

	/// Sets the percentile that the bound applies to.
	pub fn with_percentile(mut self, percentile: Percentile) -> Self {
		self.percentile = Some(percentile);
		self
	}

	/// Sets the analyzer of a percentile check. The build refuses an analyzer
	/// with no percentile.
	pub fn with_analyzer(mut self, analyzer: impl StatisticalAnalyzer + 'static) -> Self {
		self.analyzer = Some(Arc::new(analyzer));
		self
	}
}

impl TypeBuilder<WcetConfig> for WcetConfigBuilder {
	type Error = TestingError;

	fn build(self) -> Result<WcetConfig, Self::Error> {
		let duration = self.duration.ok_or(TestingError::InvalidTimingConstraint)?;
		let percentile = match (self.percentile, self.analyzer) {
			(Some(percentile), analyzer) => Some(WcetPercentile { percentile, analyzer }),
			(None, None) => None,
			// An analyzer computes the percentile, so it needs one.
			(None, Some(_)) => return Err(TestingError::InvalidTimingConstraint),
		};

		Ok(WcetConfig { duration, percentile })
	}
}

#[cfg(test)]
impl WcetConfig {
	/// A bound of `millis` milliseconds on the longest measured duration.
	pub(crate) fn of_millis(millis: u64) -> Self {
		WcetConfig { duration: Duration::from_millis(millis), percentile: None }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::TestResult;

	/// The builder of a WCET bound of 100 ms.
	fn of_100_ms() -> WcetConfigBuilder {
		WcetConfigBuilder::default().with_duration(Duration::from_millis(100))
	}

	// The builder keeps the duration, and the percentile and the analyzer that
	// the row sets.
	crate::tb_cases! {
		fn wcet_config_builder(
			(builder, percentile, has_analyzer): (WcetConfigBuilder, Option<Percentile>, bool)
		) -> TestResult {
			let config = builder.build()?;

			let check = config.percentile.as_ref();
			let analyzed = check.is_some_and(|check| check.analyzer.is_some());
			let kept = (config.duration, check.map(|check| check.percentile), analyzed);
			assert_eq!(kept, (Duration::from_millis(100), percentile, has_analyzer));
			Ok(())
		}

		cases {
			duration_alone => (of_100_ms(), None, false),
			with_a_percentile => (of_100_ms().with_percentile(Percentile::P99), Some(Percentile::P99), false),
			with_a_percentile_and_an_analyzer => (
				of_100_ms().with_percentile(Percentile::P99).with_analyzer(DefaultStatisticalAnalyzer),
				Some(Percentile::P99),
				true,
			),
		}
	}

	// The build refuses a bound with no duration, and an analyzer with no
	// percentile to compute.
	crate::tb_cases! {
		fn the_build_refuses(builder: WcetConfigBuilder) {
			let built = builder.build();
			assert!(matches!(built, Err(TestingError::InvalidTimingConstraint)));
		}

		cases {
			a_bound_with_no_duration => WcetConfigBuilder::default(),
			an_analyzer_with_no_percentile => of_100_ms().with_analyzer(DefaultStatisticalAnalyzer),
		}
	}
}
