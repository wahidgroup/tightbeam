//! FDR integration tests using canonical CSP examples
//!
//! These tests validate the FDR refinement checking implementation using
//! well-known CSP examples from the FDR Manual:
//! - Tennis Game Scoring System (state transitions, trace refinement)
//! - Dining Philosophers (deadlock detection)

#![cfg(feature = "testing-fdr")]

mod diners;
mod tennis;
