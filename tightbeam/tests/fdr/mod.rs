//! FDR integration tests using canonical CSP examples
//!
//! These tests validate the FDR refinement checking implementation using
//! well-known CSP examples from the FDR Manual:
//! - Tennis Game Scoring System (state transitions, trace refinement)
//! - Dining Philosophers (deadlock detection)
//! - Trace Analysis (FdrTraceExt methods demonstration)

mod diners;
mod tennis;
mod trace_analysis;
