//! The integration tests of TightBeam.
//!
//! Each module holds the test suite of one component of the TightBeam protocol.

// Tests are exempt from the zero-copy `Arc::clone` rule (workspace lints).
#![allow(clippy::clone_on_ref_ptr)]
// Tests are exempt from the zero-panic index and arithmetic lints (workspace
// lints): an index out of range fails its test at its location.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
// Raw `unwrap()` is banned crate-wide: test cases propagate with `?`, and
// helpers state their invariant through `expect`.
#![deny(clippy::unwrap_used)]

// The shared test helpers.
mod common;
// The rules over the crate's own sources.
mod tooling;
// The job and pipeline tests.
mod jobs;

// The instrumentation tests.
#[cfg(feature = "instrument")]
mod instrumentation;

// The protocol integration tests.
#[cfg(feature = "full")]
mod tightbeam_core;

// The frame encoding tests of the core protocol.
#[cfg(feature = "full")]
mod protocol_core;

#[cfg(feature = "transport")]
mod transport;

// The one decider for a scenario's pass or fail.
#[cfg(feature = "testing")]
mod scenario_verdict;

// The tests of FDR refinement checking.
#[cfg(feature = "testing-fdr")]
mod fdr;

// The integration tests of timing verification.
#[cfg(all(feature = "testing-timing", feature = "testing-fdr", feature = "instrument"))]
mod timing;

// The integration tests of schedulability analysis.
#[cfg(all(
	feature = "testing-timing",
	feature = "testing-schedulability",
	feature = "testing-fdr"
))]
mod schedulability;

// The colony tests.
#[cfg(feature = "colony")]
mod colony;

// The fault injection tests.
#[cfg(feature = "testing-fault")]
mod fault;

// The FMEA tests.
#[cfg(feature = "testing-fmea")]
mod fmea;

// The Delay-Tolerant Networking tests.
#[cfg(feature = "full")]
mod dtn;

// The security tests.
#[cfg(feature = "transport")]
mod security;

// The payment processing gateway tests.
#[cfg(feature = "colony")]
mod payments;

// The reading of a trace with no gate decision.
#[cfg(feature = "testing")]
mod gate;

// The refusals of `ScenarioConfigBuilder::build`.
#[cfg(feature = "testing")]
mod config;

// Teardown on the panic path.
#[cfg(feature = "testing")]
mod teardown;

// Properties over the wire types.
#[cfg(feature = "testing-property")]
mod property;

// The seams an outside crate fills with parts of its own.
#[cfg(all(feature = "transport", feature = "testing", feature = "hpke"))]
mod seams;
