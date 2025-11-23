//! FMEA (Failure Mode and Effects Analysis) module
//!
//! Provides automatic FMEA report generation from fault injection results.
//! Integrates with FDR verification to analyze failure modes, effects,
//! and criticality based on CSP reachability analysis.

mod analysis;
mod export;
mod report;

pub use analysis::{calculate_detection, calculate_severity, convert_occurrence};
pub use export::FmeaArtifact;
pub use report::{generate_fmea_report, FailureMode, FmeaConfig, FmeaReport, SeverityScale};
