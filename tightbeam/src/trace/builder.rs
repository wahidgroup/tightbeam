//! Builder patterns for trace configuration

use core::fmt;

#[cfg(feature = "instrument")]
use std::sync::Arc;

#[cfg(feature = "instrument")]
use crate::instrumentation::{EventSink, TbInstrumentationConfig};

use super::collector::TraceConfig;

#[cfg(feature = "logging")]
use super::logging::LoggerConfig;

/// Builder for TraceConfig
#[derive(Default)]
pub struct TraceConfigBuilder {
	#[cfg(feature = "instrument")]
	instrumentation: Option<TbInstrumentationConfig>,
	#[cfg(feature = "instrument")]
	sink: Option<Arc<dyn EventSink>>,
	#[cfg(feature = "logging")]
	logger: Option<LoggerConfig>,
}

impl fmt::Debug for TraceConfigBuilder {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut s = f.debug_struct("TraceConfigBuilder");
		#[cfg(feature = "instrument")]
		s.field("instrumentation", &self.instrumentation);
		#[cfg(feature = "instrument")]
		s.field("sink", &self.sink.as_ref().map(|_| "<dyn EventSink>"));
		#[cfg(feature = "logging")]
		s.field("logger", &self.logger);
		s.finish()
	}
}

impl TraceConfigBuilder {
	#[cfg(feature = "instrument")]
	pub fn with_instrumentation(mut self, config: TbInstrumentationConfig) -> Self {
		self.instrumentation = Some(config);
		self
	}

	/// Inject a custom event sink; replaces the default bounded in-memory
	/// buffer entirely (retention policy becomes the sink's decision).
	#[cfg(feature = "instrument")]
	pub fn with_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
		self.sink = Some(sink);
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
			#[cfg(feature = "instrument")]
			sink: self.sink,
			#[cfg(feature = "logging")]
			logger: self.logger,
		}
	}
}
