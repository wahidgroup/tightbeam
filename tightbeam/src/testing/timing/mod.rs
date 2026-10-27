//! The timing verification of real-time systems.
//!
//! It verifies the WCET (worst-case execution time) bounds and deadlines of
//! real-time systems, with CSP process specifications and instrumentation
//! events.

use std::time::Duration;

mod constraints;
#[cfg(feature = "testing-timing")]
mod csp;
mod deadline;
mod export;
mod jitter;
mod path;
mod statistics;
mod verification;
mod violations;
mod wcet;

pub use constraints::{TimingConstraint, TimingConstraints};
#[cfg(feature = "testing-timing")]
pub use csp::{ClockVariable, TimedTransition, TimingGuard};
pub use deadline::{Deadline, DeadlineBuilder};
pub use export::TimingVerificationArtifact;
pub use jitter::{DecorrelatedJitterCalculator, JitterCalculator, MinMaxJitter, StdDevJitter, VarianceJitter};
pub use path::{ExecutionPath, PathWcet};
pub use statistics::{
	ConfidenceIntervals, CustomMetric, DefaultStatisticalAnalyzer, Percentile, PercentileValue, StatisticalAnalyzer,
	StatisticalMeasures,
};
pub use verification::TimingVerificationResult;
pub use violations::{DeadlineMiss, JitterViolation, PathWcetViolation, TimingSlackViolation, TimingViolation};
pub use wcet::{WcetConfig, WcetConfigBuilder, WcetPercentile};

/// The nanoseconds of `duration`, saturated at `u64::MAX`, the one form in
/// which every timing bound compares with a measure.
pub(crate) fn saturating_nanos(duration: Duration) -> u64 {
	u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}
