//! Spec-driven testing contracts
//!
//! This module defines the `TBSpec` trait and verification algorithm
//! for pure spec-driven CBVOC testing. Specs declaratively describe
//! expected behavior; the framework automatically verifies traces.

use crate::error::ReceivedExpectedError;
use crate::policy::TransitStatus;
use crate::testing::assertions::AssertionContract;
use crate::trace::{ConsumedTrace, ExecutionMode};
use crate::utils::urn::Urn;
use crate::Frame;

use super::error::{AssertionViolationDetail, GateDecisionMismatch, SpecViolation};

#[cfg(feature = "instrument")]
use super::error::EventOrderViolationDetail;

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

	/// Required instrumentation event URNs (if instrumentation feature enabled)
	#[cfg(feature = "instrument")]
	fn required_events(&self) -> &[Urn<'static>] {
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
		return Err(SpecViolation::ModeMismatch(ReceivedExpectedError {
			received: actual_mode,
			expected: spec.mode(),
		}));
	}

	// 2. Verify gate decision (if spec constrains it)
	if let Some(expected_decision) = spec.expected_gate_decision() {
		if trace.gate_decision != Some(expected_decision) {
			return Err(SpecViolation::GateDecisionMismatch(GateDecisionMismatch {
				expected: expected_decision,
				actual: trace.gate_decision,
			}));
		}
	}

	// 3. Verify all assertion contracts
	for contract in spec.required_assertions() {
		if !contract.is_satisfied_by(&trace.assertions) {
			let actual_count = trace.count_assertions(&contract.label, contract.tag_filter.as_deref());
			return Err(SpecViolation::AssertionViolation(AssertionViolationDetail {
				label: contract.label.clone(),
				tags: contract.tag_filter.clone(),
				expected: contract.cardinality.describe(),
				actual: actual_count,
			}));
		}
	}

	// 4. Verify instrumentation event ordering (if instrumentation feature enabled)
	#[cfg(feature = "instrument")]
	{
		let required_kinds = spec.required_events();
		if !required_kinds.is_empty() {
			let mut idx = 0;
			for ev in trace.instrument_events.iter() {
				if idx < required_kinds.len() && ev.urn == required_kinds[idx] {
					idx += 1;
				}
			}
			if idx != required_kinds.len() {
				return Err(SpecViolation::EventOrderViolation(EventOrderViolationDetail {
					expected_kind: required_kinds[idx].clone(),
					position: idx,
				}));
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
