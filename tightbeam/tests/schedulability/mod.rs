//! Schedulability integration tests
//!
//! Tests combining schedulability analysis with CSP processes and FDR verification.

#![cfg(all(
	feature = "testing-timing",
	feature = "testing-schedulability",
	feature = "testing-fdr"
))]

mod edf_basic;
mod rma_basic;
mod violations;
