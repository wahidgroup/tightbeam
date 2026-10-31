//! The integration tests of timing verification.
//!
//! - `wcet` holds the durations that a scenario records to the WCET bounds of a CSP process.
//! - `deadline` holds the branches of an FDR exploration to the deadline of a CSP process.

mod deadline;
mod wcet;
