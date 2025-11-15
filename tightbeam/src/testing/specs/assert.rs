//! Spec-driven testing contracts
//!
//! This module defines the `TBSpec` trait and verification algorithm
//! for pure spec-driven CBVOC testing. Specs declaratively describe
//! expected behavior; the framework automatically verifies traces.

use crate::policy::TransitStatus;
use crate::testing::assertions::{AssertionContract, AssertionLabel};
use crate::testing::trace::{ConsumedTrace, ExecutionMode};
use crate::Frame;

#[cfg(feature = "instrument")]
use crate::instrumentation::TbEventKind;

use std::fmt;

/// Spec trait defining expected test behavior.
///
/// Implementors declare:
/// - Execution mode (accept/reject/error)
/// - Required phase sequence
/// - Required assertion contracts
/// - Gate decision expectations
/// - Response constraints
///
/// The `verify_trace` function validates captured traces against specs.
pub trait TBSpec {
	/// Unique identifier for this spec
	fn id(&self) -> &'static str;

	/// Expected execution mode
	fn mode(&self) -> ExecutionMode;

	/// Required instrumentation event kinds (if instrumentation feature enabled)
	#[cfg(feature = "instrument")]
	fn required_event_kinds(&self) -> &[TbEventKind] {
		&[]
	}

	/// Required assertion contracts with cardinality
	fn required_assertions(&self) -> &[AssertionContract];

	/// Expected gate decision (None = any decision acceptable)
	fn expected_gate_decision(&self) -> Option<TransitStatus> {
		None
	}

	/// Custom response validation logic
	fn validate_response(&self, _frame: &Frame) -> bool {
		true
	}

	/// Custom trace validation logic
	fn validate_trace(&self, _trace: &ConsumedTrace) -> Result<(), SpecViolation> {
		Ok(())
	}
}

/// Spec violation error type
#[derive(Clone, Debug, PartialEq)]
pub enum SpecViolation {
	/// Execution mode mismatch
	ModeMismatch {
		expected: ExecutionMode,
		actual: ExecutionMode,
	},
	/// Response assertion mismatch (presence handled via AssertionViolation on Response phase)
	ResponseUnexpectedPresence,
	ResponseUnexpectedAbsence,
	/// Gate decision mismatch
	GateDecisionMismatch {
		expected: TransitStatus,
		actual: Option<TransitStatus>,
	},
	/// Assertion contract violated
	AssertionViolation {
		label: AssertionLabel,
		tags: Option<Vec<&'static str>>,
		expected: String,
		actual: usize,
	},
	/// Event ordering violation (instrumentation)
	#[cfg(feature = "instrument")]
	EventOrderViolation {
		expected_kind: TbEventKind,
		position: usize,
	},
	/// Event count mismatch
	#[cfg(feature = "instrument")]
	EventCountMismatch {
		kind: TbEventKind,
		expected: usize,
		actual: usize,
	},
	/// Custom validation failed
	CustomValidationFailed {
		reason: String,
	},
	/// Response validation failed
	ResponseValidationFailed,
}

impl fmt::Display for SpecViolation {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ModeMismatch { expected, actual } => {
				write!(
					f,
					"Execution mode mismatch: expected {}, got {}",
					expected.as_str(),
					actual.as_str()
				)
			}
			Self::ResponseUnexpectedPresence => write!(f, "Response present but spec forbids it"),
			Self::ResponseUnexpectedAbsence => write!(f, "Response absent but spec requires it"),
			Self::GateDecisionMismatch { expected, actual } => {
				write!(f, "Gate decision mismatch: expected {expected:?}, got {actual:?}")
			}
			Self::AssertionViolation { label, tags, expected, actual } => {
				let tag_desc = if let Some(ref t) = tags {
					format!(" with tags {:?}", t)
				} else {
					String::new()
				};
				write!(
					f,
					"Assertion contract violated: {label:?}{tag_desc} expected {expected}, found {actual}"
				)
			}
			#[cfg(feature = "instrument")]
			Self::EventOrderViolation { expected_kind, position } => {
				write!(f, "Event order violation: expected {expected_kind:?} at position {position}")
			}
			#[cfg(feature = "instrument")]
			Self::EventCountMismatch { kind, expected, actual } => {
				write!(f, "Event count mismatch: {kind:?} expected {expected}, found {actual}")
			}
			Self::CustomValidationFailed { reason } => {
				write!(f, "Custom validation failed: {reason}")
			}
			Self::ResponseValidationFailed => {
				write!(f, "Response validation failed")
			}
		}
	}
}

impl std::error::Error for SpecViolation {}

/// Verify captured trace against spec contract.
///
/// This is the core verification algorithm:
/// 1. Verify execution mode matches spec
/// 2. Verify gate decision (if spec constrains it)
/// 3. Verify response presence/absence
/// 4. Verify all assertion contracts
/// 5. Verify phase ordering (if testing feature enabled)
/// 6. Custom response validation
/// 7. Custom trace validation
pub fn verify_trace<S: TBSpec>(spec: &S, trace: &ConsumedTrace) -> Result<(), SpecViolation> {
	// 1. Verify execution mode
	let actual_mode = trace.execution_mode();
	if actual_mode != spec.mode() {
		return Err(SpecViolation::ModeMismatch { expected: spec.mode(), actual: actual_mode });
	}

	// 2. Verify gate decision (if spec constrains it)
	if let Some(expected_decision) = spec.expected_gate_decision() {
		if trace.gate_decision != Some(expected_decision) {
			return Err(SpecViolation::GateDecisionMismatch {
				expected: expected_decision,
				actual: trace.gate_decision,
			});
		}
	}

	// 3. Verify all assertion contracts
	for contract in spec.required_assertions() {
		if !contract.is_satisfied_by(&trace.assertions) {
			let actual_count = trace.count_assertions(&contract.label, contract.tag_filter.as_deref());
			return Err(SpecViolation::AssertionViolation {
				label: contract.label.clone(),
				tags: contract.tag_filter.clone(),
				expected: contract.cardinality.describe(),
				actual: actual_count,
			});
		}
	}

	// 4. Verify instrumentation event ordering (if instrumentation feature enabled)
	#[cfg(feature = "instrument")]
	{
		let required_kinds = spec.required_event_kinds();
		if !required_kinds.is_empty() {
			let mut idx = 0;
			for ev in trace.instrument_events.iter() {
				if idx < required_kinds.len() && ev.kind == required_kinds[idx] {
					idx += 1;
				}
			}
			if idx != required_kinds.len() {
				return Err(SpecViolation::EventOrderViolation { expected_kind: required_kinds[idx], position: idx });
			}
		}
	}

	// 5. Custom response validation
	if let Some(ref response) = trace.response {
		if !spec.validate_response(response) {
			return Err(SpecViolation::ResponseValidationFailed);
		}
	}

	// 6. Custom trace validation
	spec.validate_trace(trace)?;

	Ok(())
}
