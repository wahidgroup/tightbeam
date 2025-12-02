//! Job orchestration utilities
//!
//! This module provides the `job!` macro for creating zero-sized-type (ZST) command pattern jobs,
//! and the `Pipeline` trait for composing jobs with Result-based functional pipelines.
//!
//! # Traits
//!
//! - [`Job`] - Marker trait for synchronous jobs
//! - [`AsyncJob`] - Marker trait for asynchronous jobs
//! - [`Pipeline`] - Trait for composing results in a functional pipeline

#[macro_use]
pub mod job;
pub mod pipeline;

pub use job::{AsyncJob, Job};
pub use pipeline::*;
