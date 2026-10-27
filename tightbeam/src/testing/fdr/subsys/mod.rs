//! The subsystems of FDR exploration, one per module.
//!
//! - [`cache`]: the memoization cache of refinement checking.
//! - [`engine`]: [`FdrExplorer`], which runs the checks through the other subsystems.
//! - [`exploration`]: the walk of each seed through the state space.
//! - [`export`]: the CSPM export of a process for FDR4.
//! - [`extensions`]: the FDR analysis of a consumed trace.
//! - `recorder` (feature `instrument`): the exploration events of a trace.
//! - [`refinement`]: trace, failures, and divergence refinement.
//! - `timing` (feature `testing-timing`): the timing checks of exploration.

pub mod cache;
pub mod engine;
pub mod exploration;
pub mod export;
pub mod extensions;
#[cfg(feature = "instrument")]
mod recorder;
pub mod refinement;

#[cfg(feature = "testing-timing")]
pub mod timing;

pub use cache::DefaultCache;
pub use engine::{DefaultFdrExplorer, FdrExplorer};
pub use exploration::DefaultExplorationEngine;
pub use export::*;
pub use extensions::*;
pub use refinement::DefaultRefinementChecker;
