//! Layer 3: FDR/Refinement checking
//!
//! This module provides bounded refinement checking following CSP theory.
//! Feature gated: requires `testing-fdr`

mod config;
mod explorer;
mod subsys;

#[cfg(test)]
mod tests;

pub use config::*;
pub use explorer::*;
pub use subsys::*;
