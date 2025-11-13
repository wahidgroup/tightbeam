//! AFL fuzz targets
//!
//! These modules contain fuzz targets that are compiled as separate binaries
//! when built with `cargo afl build` and the `fuzzing` cfg flag.

#[cfg(fuzzing)]
pub mod simple_workflow;

#[cfg(fuzzing)]
pub mod complex_workflow;

#[cfg(fuzzing)]
pub mod verification;
