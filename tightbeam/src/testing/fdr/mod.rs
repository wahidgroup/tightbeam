//! Layer 3: Failures-Divergences Refinement checking
//!
//! This module provides bounded refinement checking following CSP theory.
//! Feature gated: requires `testing-fdr`

mod config;
mod explorer;
mod subsys;

pub use config::*;
pub use explorer::*;
pub use subsys::*;
