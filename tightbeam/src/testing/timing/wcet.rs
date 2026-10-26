//! The WCET (Worst-Case Execution Time) configuration and its builder.

use std::sync::Arc;
use std::time::Duration;

use super::statistics::{Percentile, StatisticalAnalyzer};
use crate::builder::TypeBuilder;
use crate::testing::error::TestingError;

/// A WCET bound on an event, with an optional percentile and analyzer.
#[derive(Debug, Clone)]
pub struct WcetConfig {
	/// The longest duration that the bound allows.
	pub duration: Duration,
	/// The percentile of the measured durations that the bound applies to,
	/// or `None` to bound the longest one.
	pub percentile: Option<Percentile>,
	/// The analyzer of a percentile check, or `None` for
	/// [`DefaultStatisticalAnalyzer`](super::DefaultStatisticalAnalyzer).
	pub analyzer: Option<Arc<dyn StatisticalAnalyzer>>,
}

/// The builder of a [`WcetConfig`], whose build requires a duration.
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

	/// Sets the analyzer of a percentile check.
	pub fn with_analyzer(mut self, analyzer: impl StatisticalAnalyzer + 'static) -> Self {
		self.analyzer = Some(Arc::new(analyzer));
		self
	}
}

impl TypeBuilder<WcetConfig> for WcetConfigBuilder {
	type Error = TestingError;

	fn build(self) -> Result<WcetConfig, Self::Error> {
		let duration = self.duration.ok_or(TestingError::InvalidTimingConstraint)?;
		Ok(WcetConfig { duration, percentile: self.percentile, analyzer: self.analyzer })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::timing::DefaultStatisticalAnalyzer;

	/// One row of the [`WcetConfigBuilder`] case table.
	struct WcetConfigTestCase {
		percentile: Option<Percentile>,
		has_analyzer: bool,
	}

	impl WcetConfigTestCase {
		/// A WCET of 100 ms with the percentile and the analyzer of the case.
		fn built(&self) -> Result<WcetConfig, TestingError> {
			let duration = Duration::from_millis(100);
			let mut builder = WcetConfigBuilder::default().with_duration(duration);

			if let Some(percentile) = self.percentile {
				builder = builder.with_percentile(percentile);
			}

			if self.has_analyzer {
				builder = builder.with_analyzer(DefaultStatisticalAnalyzer);
			}

			builder.build()
		}
	}

	// The builder keeps the duration, and each option the case sets.
	crate::tb_cases! {
		fn wcet_config_builder(case: WcetConfigTestCase) -> Result<(), TestingError> {
			let config = case.built()?;
			assert_eq!(config.duration, Duration::from_millis(100));
			assert_eq!(config.percentile, case.percentile);
			assert_eq!(config.analyzer.is_some(), case.has_analyzer);
			Ok(())
		}

		cases {
			duration_alone => WcetConfigTestCase { percentile: None, has_analyzer: false },
			with_a_percentile => WcetConfigTestCase { percentile: Some(Percentile::P99), has_analyzer: false },
			with_an_analyzer => WcetConfigTestCase { percentile: None, has_analyzer: true },
			with_a_percentile_and_an_analyzer => WcetConfigTestCase { percentile: Some(Percentile::P99), has_analyzer: true },
		}
	}

	#[test]
	fn test_wcet_config_builder_missing_duration() {
		let result = WcetConfigBuilder::default().build();
		assert!(matches!(result, Err(TestingError::InvalidTimingConstraint)));
	}
}
