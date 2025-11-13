//! AFL fuzz integration tests

#![cfg(all(feature = "std", feature = "testing-csp"))]

#[cfg(fuzzing)]
#[path = "fuzz"]
mod fuzz {
    pub mod complex_workflow;
    pub mod simple_workflow;
}
