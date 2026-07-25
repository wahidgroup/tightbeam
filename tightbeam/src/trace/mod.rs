//! Trace collection and logging subsystem

mod assertion;
mod builder;
mod collector;

#[cfg(feature = "logging")]
mod logging;

// Re-export trace types
pub use assertion::{AssertionValue, IsNone, IsSome, Presence, RatioLimit};
pub use builder::TraceConfigBuilder;
pub use collector::{EventBuilder, EventValue, IntoEventLabel, TraceCollector, TraceConfig};

#[cfg(any(test, feature = "testing"))]
pub use assertion::{Assertion, AssertionLabel};
#[cfg(any(test, feature = "testing"))]
pub use collector::{ConsumedTrace, ExecutionMode};

// Export logging types
#[cfg(feature = "logging")]
pub use logging::{
	LogBackend, LogError, LogFilter, LogLevel, LogRecord, LoggerConfig, MultiplexBackend, StdoutBackend,
};
