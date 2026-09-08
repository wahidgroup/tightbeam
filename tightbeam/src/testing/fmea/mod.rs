//! FMEA (Failure Mode and Effects Analysis) module
//!
//! Provides automatic FMEA report generation from fault injection results.
//! Integrates with FDR verification to analyze failure modes, effects,
//! and criticality based on CSP reachability analysis.

mod analysis;
mod export;
mod report;

pub use export::FmeaArtifact;
pub use report::{FailureMode, FmeaConfig, FmeaReport, SeverityScale};
