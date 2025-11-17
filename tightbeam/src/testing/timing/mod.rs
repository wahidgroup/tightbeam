//! Timing and real-time verification module
//!
//! Provides WCET (Worst-Case Execution Time) verification and deadline checking
//! for real-time systems. Integrates with CSP process specifications and
//! instrumentation events.

#[cfg(feature = "testing-timing")]
mod csp;
mod constraints;
mod deadline;
mod export;
mod path;
mod verification;
mod violations;
mod wcet;

#[cfg(feature = "testing-timing")]
pub use csp::{ClockVariable, TimedTransition, TimingGuard};
pub use constraints::{TimingConstraint, TimingConstraints};
pub use deadline::{Deadline, DeadlineBuilder};
pub use export::TimingVerificationArtifact;
pub use path::{ExecutionPath, PathWcet};
pub use verification::TimingVerificationResult;
pub use violations::{DeadlineMiss, JitterViolation, PathWcetViolation, TimingSlackViolation, TimingViolation};
pub use wcet::{WcetConfig, WcetConfigBuilder};
