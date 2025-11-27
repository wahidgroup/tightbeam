//! Trace collection and logging subsystem

mod collector;

#[cfg(feature = "logging")]
mod logging;

// Re-export trace types (maintain backward compatibility)
pub use collector::{
	ConsumedTrace, EventBuilder, EventValue, ExecutionMode, IntoEventLabel, TraceCollector, TraceConfig,
};

// Export logging types
#[cfg(feature = "logging")]
pub use logging::{
	LogBackend, LogError, LogFilter, LogLevel, LogRecord, LoggerConfig, MultiplexBackend, StdoutBackend,
};
