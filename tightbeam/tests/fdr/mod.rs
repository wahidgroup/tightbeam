//! The FDR integration tests, built on canonical CSP examples.
//!
//! These tests check FDR refinement checking against well-known CSP examples
//! from the FDR Manual:
//! - Tennis Game Scoring System: state transitions and trace refinement.
//! - Dining Philosophers: deadlock detection.
//! - Trace Analysis: the methods of `FdrTraceExt`.
//!
//! The `exploration` suite builds an exploration engine, and the `refinement`
//! suite builds a refinement checker, through the public API alone, as an
//! outside crate must.

mod diners;
mod refinement;
mod tennis;
mod trace_analysis;

#[cfg(feature = "instrument")]
mod exploration;
