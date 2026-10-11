//! URN specification builders
//!
//! Provides builders for programmatic construction of URN specifications.

pub mod spec;
pub mod urn;

pub use spec::{Constraint, FieldConfig, NssFormat, UrnSpecBuilder};
pub use urn::UrnBuilder;
