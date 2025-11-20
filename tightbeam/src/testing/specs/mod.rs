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

#[cfg(feature = "testing-csp")]
pub mod csp;

// Re-exports
pub use assert::{verify_trace, TBSpec};
pub use error::{AssertionViolationDetail, GateDecisionMismatch, SpecViolation};

#[cfg(feature = "instrument")]
pub use error::{EventCountMismatchDetail, EventOrderViolationDetail};

#[cfg(feature = "testing-csp")]
pub use csp::*;
