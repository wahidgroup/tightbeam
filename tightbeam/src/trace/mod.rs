//! The subsystem that collects traces and, under `logging`, writes log records.

mod assertion;
mod builder;
mod collector;

#[cfg(feature = "colony")]
mod handle;
#[cfg(feature = "logging")]
mod logging;

pub use assertion::{AssertionValue, IsNone, IsSome, Presence, RatioLimit};
pub use builder::TraceConfigBuilder;
pub use collector::{EventBuilder, EventValue, IntoEventLabel, TraceCollector, TraceConfig};

#[cfg(any(all(feature = "instrument", feature = "transport"), feature = "testing-fdr"))]
pub(crate) use collector::InternalEvent;
#[cfg(feature = "colony")]
pub(crate) use handle::TraceHandle;

#[cfg(any(test, feature = "testing"))]
pub use assertion::{Assertion, AssertionLabel};
#[cfg(all(feature = "instrument", any(test, feature = "testing")))]
pub use collector::EventRecordTruncated;
#[cfg(any(test, feature = "testing"))]
pub use collector::{ConsumedTrace, Exchange, ExecutionMode};

#[cfg(feature = "logging")]
pub use collector::TraceStateShared;
#[cfg(feature = "logging")]
pub use logging::{
	LogBackend, LogError, LogFilter, LogLevel, LogRecord, LoggerConfig, MultiplexBackend, StdoutBackend,
};
