//! FDR subsystems
//!
//! This module contains the modular subsystems for FDR functionality.

pub mod cache;
pub mod engine;
pub mod exploration;
pub mod export;
pub mod extensions;
pub mod refinement;

// Re-export main types and traits
pub use cache::DefaultCache;
pub use engine::{DefaultFdrExplorer, FdrExplorer};
pub use exploration::DefaultExplorationEngine;
pub use export::*;
pub use extensions::*;
pub use refinement::DefaultRefinementChecker;
