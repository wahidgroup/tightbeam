//! Integration tests for TightBeam
//!
//! Organized test suites for various components of the TightBeam protocol.

// Common test helpers
mod common;

// Instrumentation tests
#[cfg(feature = "instrument")]
mod instrumentation;

// Core protocol tests
#[cfg(feature = "full")]
mod tightbeam_core;

#[cfg(feature = "transport")]
mod transport;

// X.509 tests
#[cfg(feature = "x509")]
mod x509;

// FDR refinement checking tests
#[cfg(feature = "testing-fdr")]
mod fdr;

// Timing verification integration tests
#[cfg(all(feature = "testing-timing", feature = "testing-fdr", feature = "instrument"))]
mod timing;

// Schedulability analysis integration tests
#[cfg(all(
	feature = "testing-timing",
	feature = "testing-schedulability",
	feature = "testing-fdr"
))]
mod schedulability;

// Colony tests
#[cfg(feature = "colony")]
mod colony;

// Fault injection tests
#[cfg(feature = "testing-fault")]
mod fault;

// FMEA tests
#[cfg(feature = "testing-fmea")]
mod fmea;

// Delay-Tolerant Networking tests
#[cfg(all(feature = "full"))]
mod dtn;

// DLT Network test
// #[cfg(feature = "full")]
// mod proof;
