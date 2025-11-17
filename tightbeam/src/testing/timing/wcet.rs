//! WCET (Worst-Case Execution Time) configuration

use std::sync::Arc;
use std::time::Duration;

use crate::builder::TypeBuilder;
use crate::testing::error::TestingError;
use crate::utils::statistics::{Percentile, StatisticalAnalyzer};

/// WCET configuration with optional percentile and statistical analyzer.
#[derive(Debug, Clone)]
pub struct WcetConfig {
	/// Maximum allowed duration
	pub duration: Duration,
	/// Percentile level (None = max, current behavior)
	pub percentile: Option<Percentile>,
	/// Optional statistical analyzer (None = use default)
	pub analyzer: Option<Arc<dyn StatisticalAnalyzer>>,
}

/// Builder for creating `WcetConfig` instances.
#[derive(Debug, Default, Clone)]
pub struct WcetConfigBuilder {
	duration: Option<Duration>,
	percentile: Option<Percentile>,
	analyzer: Option<Arc<dyn StatisticalAnalyzer>>,
}

impl WcetConfigBuilder {
	/// Set the WCET duration.
	pub fn with_duration(mut self, duration: Duration) -> Self {
		self.duration = Some(duration);
		self
	}

	/// Set the percentile level.
	pub fn with_percentile(mut self, percentile: Percentile) -> Self {
		self.percentile = Some(percentile);
		self
	}

	/// Set the statistical analyzer.
	pub fn with_analyzer(mut self, analyzer: Arc<dyn StatisticalAnalyzer>) -> Self {
		self.analyzer = Some(analyzer);
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
	use crate::utils::statistics::DefaultStatisticalAnalyzer;

	/// Test case for WcetConfigBuilder
	struct WcetConfigTestCase {
		duration_ms: u64,
		percentile: Option<Percentile>,
		has_analyzer: bool,
		expected_duration_ms: u64,
		expected_percentile: Option<Percentile>,
		expected_has_analyzer: bool,
	}

	const WCET_CONFIG_TEST_CASES: &[WcetConfigTestCase] = &[
		WcetConfigTestCase {
			duration_ms: 100,
			percentile: None,
			has_analyzer: false,
			expected_duration_ms: 100,
			expected_percentile: None,
			expected_has_analyzer: false,
		},
		WcetConfigTestCase {
			duration_ms: 100,
			percentile: Some(Percentile::P99),
			has_analyzer: false,
			expected_duration_ms: 100,
			expected_percentile: Some(Percentile::P99),
			expected_has_analyzer: false,
		},
		WcetConfigTestCase {
			duration_ms: 100,
			percentile: None,
			has_analyzer: true,
			expected_duration_ms: 100,
			expected_percentile: None,
			expected_has_analyzer: true,
		},
		WcetConfigTestCase {
			duration_ms: 100,
			percentile: Some(Percentile::P99),
			has_analyzer: true,
			expected_duration_ms: 100,
			expected_percentile: Some(Percentile::P99),
			expected_has_analyzer: true,
		},
	];

	/// Run WcetConfig test case
	fn run_wcet_config_test_case(case: &WcetConfigTestCase) -> Result<(), TestingError> {
		let duration = Duration::from_millis(case.duration_ms);
		let mut builder = WcetConfigBuilder::default().with_duration(duration);

		if let Some(percentile) = case.percentile {
			builder = builder.with_percentile(percentile);
		}

		if case.has_analyzer {
			let analyzer = Arc::new(DefaultStatisticalAnalyzer);
			builder = builder.with_analyzer(analyzer);
		}

		let config = builder.build()?;
		assert_eq!(config.duration, Duration::from_millis(case.expected_duration_ms));
		assert_eq!(config.percentile, case.expected_percentile);
		assert_eq!(config.analyzer.is_some(), case.expected_has_analyzer);
		Ok(())
	}

	#[test]
	fn test_wcet_config_builder() -> Result<(), TestingError> {
		for case in WCET_CONFIG_TEST_CASES {
			run_wcet_config_test_case(case)?;
		}
		Ok(())
	}

	#[test]
	fn test_wcet_config_builder_missing_duration() {
		let result = WcetConfigBuilder::default().build();
		assert!(matches!(result, Err(TestingError::InvalidTimingConstraint)));
	}
}
