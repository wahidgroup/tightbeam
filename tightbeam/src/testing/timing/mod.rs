//! Timing and real-time verification module
//!
//! Provides WCET (Worst-Case Execution Time) verification and deadline checking
//! for real-time systems. Integrates with CSP process specifications and
//! instrumentation events.

mod constraints;
mod deadline;
mod export;
mod verification;
mod violations;
mod wcet;

pub use constraints::{TimingConstraint, TimingConstraints};
pub use deadline::{Deadline, DeadlineBuilder};
pub use export::TimingVerificationArtifact;
pub use verification::TimingVerificationResult;
pub use violations::{DeadlineMiss, JitterViolation, TimingSlackViolation, TimingViolation};
pub use wcet::{WcetConfig, WcetConfigBuilder};
