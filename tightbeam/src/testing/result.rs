//! Unified scenario result structure
//!
//! This module provides `ScenarioResult`, a unified result structure that
//! aggregates all verification layers for comprehensive test reporting.

use core::fmt::{Display, Formatter};

use crate::testing::export::ScenarioResultExport;
use crate::testing::macros::BuiltAssertSpec;
use crate::testing::specs::SpecViolation;
use crate::trace::ConsumedTrace;

#[cfg(feature = "testing-fdr")]
use crate::testing::fdr::FdrVerdict;
#[cfg(feature = "testing-schedulability")]
use crate::testing::schedulability::{SchedulabilityResult, TaskSet};
#[cfg(feature = "testing-csp")]
use crate::testing::specs::csp::{CspValidationResult, Process};
#[cfg(feature = "testing-timing")]
use crate::testing::timing::{TimingConstraints, TimingVerificationResult};

/// Unified scenario result aggregating all verification layers
///
/// Provides comprehensive test context including:
/// - Layer 1: Assertion spec verification
/// - Layer 2: CSP validation
/// - Layer 3: FDR refinement checking
/// - Timing verification (WCET, deadlines, jitter, schedulability)
///
/// Owns all specification and trace data for export to formal verification tools.
/// Follows industry best practices (JUnit 5, etc.) for rich test context.
#[derive(Debug)]
pub struct ScenarioResult {
	/// Full execution trace (owned for export)
	pub trace: ConsumedTrace,

	/// Single assertion spec (for single_spec variant)
	pub assert_spec: Option<BuiltAssertSpec>,

	/// Multiple assertion specs (for multi_specs variant)
	pub assert_specs: Vec<BuiltAssertSpec>,

	/// Layer 1: Assertion spec verification (None = passed)
	pub spec_violation: Option<SpecViolation>,

	/// Layer 2: CSP validation result (None = not checked or passed)
	#[cfg(feature = "testing-csp")]
	pub csp_result: Option<CspValidationResult>,

	/// CSP process specification (owned for export)
	#[cfg(feature = "testing-csp")]
	pub process: Option<Process>,

	/// Layer 3: FDR refinement checking (None = not checked)
	#[cfg(feature = "testing-fdr")]
	pub fdr_verdict: Option<FdrVerdict>,

	/// Timing verification result (None = not checked)
	#[cfg(feature = "testing-timing")]
	pub timing_result: Option<TimingVerificationResult>,

	/// Timing constraints (owned for export)
	#[cfg(feature = "testing-timing")]
	pub timing_constraints: Option<TimingConstraints>,

	/// Task set (if schedulability analysis was performed)
	#[cfg(feature = "testing-schedulability")]
	pub task_set: Option<TaskSet>,

	/// Schedulability analysis result (if performed)
	#[cfg(feature = "testing-schedulability")]
	pub schedulability_result: Option<SchedulabilityResult>,

	/// Overall pass/fail status
	pub passed: bool,
}

impl ScenarioResult {
	/// Create a scenario result from Layer 1 (spec) verification only
	pub fn from_spec_result(result: Result<(), SpecViolation>) -> Self {
		let (spec_violation, passed) = match result {
			Ok(()) => (None, true),
			Err(violation) => (Some(violation), false),
		};

		Self {
			trace: ConsumedTrace::new(),
			assert_spec: None,
			assert_specs: Vec::new(),
			spec_violation,
			#[cfg(feature = "testing-csp")]
			csp_result: None,
			#[cfg(feature = "testing-csp")]
			process: None,
			#[cfg(feature = "testing-fdr")]
			fdr_verdict: None,
			#[cfg(feature = "testing-timing")]
			timing_result: None,
			#[cfg(feature = "testing-timing")]
			timing_constraints: None,
			#[cfg(feature = "testing-schedulability")]
			task_set: None,
			#[cfg(feature = "testing-schedulability")]
			schedulability_result: None,
			passed,
		}
	}

	/// Check if all layers passed
	pub fn all_passed(&self) -> bool {
		self.passed
	}

	/// Check if any layer failed
	pub fn has_failures(&self) -> bool {
		!self.passed
	}
}

impl Default for ScenarioResult {
	fn default() -> Self {
		Self {
			trace: ConsumedTrace::new(),
			assert_spec: None,
			assert_specs: Vec::new(),
			spec_violation: None,
			#[cfg(feature = "testing-csp")]
			csp_result: None,
			#[cfg(feature = "testing-csp")]
			process: None,
			#[cfg(feature = "testing-fdr")]
			fdr_verdict: None,
			#[cfg(feature = "testing-timing")]
			timing_result: None,
			#[cfg(feature = "testing-timing")]
			timing_constraints: None,
			#[cfg(feature = "testing-schedulability")]
			task_set: None,
			#[cfg(feature = "testing-schedulability")]
			schedulability_result: None,
			passed: true,
		}
	}
}

impl Display for ScenarioResult {
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		if self.passed {
			write!(f, "Verification passed")
		} else {
			writeln!(f, "Verification failed:")?;

			// Layer 1: Assertion spec violations
			if let Some(ref violation) = self.spec_violation {
				writeln!(f, "  [Assertion] {}", violation)?;
			}

			// Layer 2: CSP validation failures
			#[cfg(feature = "testing-csp")]
			if let Some(ref csp_res) = self.csp_result {
				if !csp_res.valid {
					writeln!(f, "  [CSP] Validation failed:")?;
					for violation in &csp_res.violations {
						writeln!(f, "    - {}", violation)?;
					}
				}
			}

			// Layer 3: FDR refinement failures
			#[cfg(feature = "testing-fdr")]
			if let Some(ref fdr_verdict) = self.fdr_verdict {
				if !fdr_verdict.passed {
					writeln!(f, "  [FDR] Refinement check failed")?;
				}
			}

			// Timing verification failures
			#[cfg(feature = "testing-timing")]
			if let Some(ref timing_res) = self.timing_result {
				if !timing_res.passed {
					writeln!(f, "  [Timing] Verification failed")?;
				}
			}

			// Schedulability analysis failures
			#[cfg(feature = "testing-schedulability")]
			if let Some(ref schedule_res) = self.schedulability_result {
				if !schedule_res.is_schedulable {
					writeln!(
						f,
						"  [Schedulability] Analysis failed: utilization {:.2}% (bound {:.2}%)",
						schedule_res.utilization * 100.0,
						schedule_res.utilization_bound * 100.0
					)?;
				}
			}

			Ok(())
		}
	}
}

// Implement ScenarioResultExport trait with stub implementations
impl ScenarioResultExport for ScenarioResult {
	/// Export to Markdown (human-readable report)
	fn to_markdown(&self) -> String {
		// Implementation deferred - return error indicating not yet implemented
		todo!("Markdown export not yet implemented")
	}

	/// Export to UPPAAL XML format for timed automata verification
	fn to_uppaal(&self) -> String {
		// Implementation deferred - return error indicating not yet implemented
		todo!("UPPAAL export not yet implemented")
	}

	/// Export to TCTL (Timed Computation Tree Logic) specification
	fn to_tctl(&self) -> String {
		// Implementation deferred - return error indicating not yet implemented
		todo!("TCTL export not yet implemented")
	}

	// Export to FDR4 format
	fn to_fdr4(&self) -> String {
		// Implementation deferred - return error indicating not yet implemented
		todo!("FDR4 export not yet implemented")
	}
}
