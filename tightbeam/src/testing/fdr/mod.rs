//! Layer 3: Failures-Divergences Refinement checking
//!
//! This module provides bounded refinement checking following CSP theory.
//! [`FdrVerdict`] reports the outcome, and the explorer that fills it is
//! behind `testing-fdr`.

mod verdict;

pub use verdict::*;

#[cfg(feature = "testing-fdr")]
mod config;
#[cfg(feature = "testing-fdr")]
mod explorer;
#[cfg(feature = "testing-fdr")]
mod subsys;

#[cfg(feature = "testing-fdr")]
pub use config::*;
#[cfg(feature = "testing-fdr")]
pub use explorer::*;
#[cfg(feature = "testing-fdr")]
pub use subsys::*;
