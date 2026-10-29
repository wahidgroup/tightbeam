//! Jobs, and the pipelines that compose them.
//!
//! The `job!` macro defines a job as a zero-sized type with a static `run`
//! function, and a [`Pipeline`] chains the results of jobs.
//!
//! # Traits
//!
//! - [`Job`] is the trait of a synchronous job.
//! - [`AsyncJob`] is the trait of an asynchronous job.
//! - [`Pipeline`] chains computations on a `Result`.

#[macro_use]
pub mod job;
pub mod pipeline;

pub use job::{AsyncJob, Job};
pub use pipeline::*;
