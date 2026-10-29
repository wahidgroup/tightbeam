//! The FDR integration tests, built on canonical CSP examples.
//!
//! These tests check the FDR refinement checker against well-known CSP
//! examples from the FDR Manual:
//! - Tennis Game Scoring System: state transitions and trace refinement.
//! - Dining Philosophers: deadlock detection.
//! - Trace Analysis: the methods of `FdrTraceExt`.
//!
//! The `exploration` suite builds an exploration engine, and the `refinement`
//! suite builds a refinement checker and a memoization cache, through the
//! public API alone, as an outside crate must. The `scenario` suite grades a
//! scenario that names a CSP model and FDR specs.

mod diners;
mod refinement;
mod scenario;
#[cfg(feature = "testing-fault")]
mod scheduler;
mod tennis;
mod trace_analysis;

#[cfg(feature = "instrument")]
mod exploration;
