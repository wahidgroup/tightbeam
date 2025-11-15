//! AFL fuzz integration tests

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "testing-csp"))]

#[cfg(fuzzing)]
#[path = "fuzz"]
mod fuzz {
    pub mod complex_workflow;
    pub mod simple_workflow;
    pub mod verification;
    pub mod chess;
}
