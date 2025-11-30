//! Builder patterns for trace configuration

use super::collector::TraceConfig;

#[cfg(feature = "logging")]
use super::logging::LoggerConfig;
#[cfg(feature = "instrument")]
use crate::instrumentation::TbInstrumentationConfig;

/// Builder for TraceConfig
#[derive(Debug, Default)]
pub struct TraceConfigBuilder {
	#[cfg(feature = "instrument")]
	instrumentation: Option<TbInstrumentationConfig>,
	#[cfg(feature = "logging")]
	logger: Option<LoggerConfig>,
}

impl TraceConfigBuilder {
	#[cfg(feature = "instrument")]
	pub fn with_instrumentation(mut self, config: TbInstrumentationConfig) -> Self {
		self.instrumentation = Some(config);
		self
	}

	#[cfg(feature = "logging")]
	pub fn with_logger(mut self, config: LoggerConfig) -> Self {
		self.logger = Some(config);
		self
	}

	pub fn build(self) -> TraceConfig {
		TraceConfig {
			#[cfg(feature = "instrument")]
			instrumentation: self.instrumentation,
			#[cfg(feature = "logging")]
			logger: self.logger,
		}
	}
}
