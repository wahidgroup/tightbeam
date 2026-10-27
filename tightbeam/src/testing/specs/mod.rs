//! The specs of the testing framework.
//!
//! It organizes the three-layer testing stack:
//! - Layer 1 (L1), the AssertSpec, verifies deterministic assertions.
//! - Layer 2 (L2), the ProcessSpec (CSP), checks a labeled transition system of external and internal events.
//! - Layer 3 (L3), FDR refinement, runs a bounded refinement check.
//!
//! Each layer builds on the previous one, and a feature flag enables it:
//! - `testing` enables the base layer, L1.
//! - `testing-csp` enables L2, and it requires `testing`.
//! - `testing-fdr` enables L3, and it requires `testing-csp`.

pub mod assert;
pub mod error;
pub mod lts;

/// The verification layer that graded a scenario.
///
/// The layers grade each run in this order. Each layer that the configuration
/// names grades the run whatever the layers before it decided. A negative test
/// names the layer it expects a rejection from through
/// [`Expect::Violation`](crate::testing::Expect).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layer {
	/// Layer 1, the assertion spec that grades the recorded trace.
	Assertion,
	/// Layer 2, the CSP process that grades the trace as a labeled transition
	/// system.
	Csp,
	/// Layer 3, the bounded refinement check over the FDR exploration.
	Refinement,
}

impl Layer {
	/// Every layer, in the order they grade a run.
	pub const ALL: [Self; 3] = [Self::Assertion, Self::Csp, Self::Refinement];
}

#[cfg(feature = "testing-csp")]
pub mod composition;
#[cfg(feature = "testing-csp")]
pub mod csp;

pub use assert::{AssertionOrderContract, ResponseContract, TBSpec};
pub use error::{
	AssertionViolationDetail, EventCountMismatchDetail, EventOrderViolationDetail, GateDecisionMismatch, SpecViolation,
	Violations,
};
pub use lts::*;

#[cfg(feature = "instrument")]
pub use assert::EventCountContract;
#[cfg(feature = "testing-csp")]
pub use composition::*;
#[cfg(feature = "testing-csp")]
pub use csp::*;
