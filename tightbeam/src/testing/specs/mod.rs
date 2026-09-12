//! Specification module for testing framework
//!
//! This module organizes the three-layer testing stack:
//! - Layer 1 (L1): AssertSpec - deterministic assertion verification
//! - Layer 2 (L2): ProcessSpec (CSP) - labeled transition systems with external/internal events
//! - Layer 3 (L3): FDR/Refinement - bounded refinement checking
//!
//! Each layer builds on the previous, with feature flags controlling availability:
//! - `testing` - Base layer (L1)
//! - `testing-csp` - L2 (requires `testing`)
//! - `testing-fdr` - L3 (requires `testing-csp`)

pub mod assert;
pub mod error;
pub mod lts;

/// The verification layer that graded a scenario.
///
/// The three layers run in order, and each one grades what the layer before
/// it accepted, so a scenario reaches Layer 3 only when Layer 1 and Layer 2
/// both had their say. A negative test names the layer it expects to be
/// rejected by through [`Expect::Violation`](crate::testing::Expect).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layer {
	/// Layer 1, the assertion spec that grades the recorded trace.
	Assertion,
	/// Layer 2, the CSP process that grades the trace as a labelled transition system.
	Csp,
	/// Layer 3, the bounded refinement check over the FDR exploration.
	Refinement,
}

#[cfg(feature = "testing-csp")]
pub mod composition;
#[cfg(feature = "testing-csp")]
pub mod csp;

// Re-exports
pub use assert::{verify_trace, TBSpec};
pub use error::{
	AssertionViolationDetail, EventCountMismatchDetail, EventOrderViolationDetail, GateDecisionMismatch, SpecViolation,
	Violations,
};
pub use lts::*;

#[cfg(feature = "testing-csp")]
pub use composition::*;
#[cfg(feature = "testing-csp")]
pub use csp::*;
