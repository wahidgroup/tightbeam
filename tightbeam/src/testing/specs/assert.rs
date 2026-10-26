//! The contracts of spec-driven testing.
//!
//! This module defines the `TBSpec` trait and the verification algorithm of
//! pure spec-driven CBVOC testing. A spec describes the expected behavior
//! declaratively, and the framework verifies each trace against it.

use super::error::{AssertionViolationDetail, GateDecisionMismatch, SpecViolation};
use crate::error::{ReceivedExpectedError, TightBeamError};
use crate::testing::assertions::AssertionContract;
use crate::trace::{ConsumedTrace, ExecutionMode};
use crate::Frame;

#[cfg(feature = "instrument")]
use super::error::EventOrderViolationDetail;
#[cfg(feature = "policy")]
use crate::policy::TransitStatus;
#[cfg(feature = "instrument")]
use crate::urn::Urn;

/// A spec, which declares the expected behavior of a test.
///
/// An implementor declares:
/// - The execution mode: accept, reject, or error.
/// - The required phase sequence.
/// - The required assertion contracts.
/// - The expected gate decision.
/// - The response constraints.
///
/// [`TBSpec::verify`] checks a captured trace against the spec.
pub trait TBSpec {
	/// The unique identifier of this spec.
	fn id(&self) -> &'static str;

	/// The expected execution mode.
	fn mode(&self) -> ExecutionMode;

	/// The instrumentation event URNs that the trace must record in order,
	/// under the `instrument` feature.
	#[cfg(feature = "instrument")]
	fn required_events(&self) -> &[Urn<'static>] {
		&[]
	}

	/// The assertion contracts that the trace must meet, each with its
	/// cardinality.
	fn required_assertions(&self) -> &[AssertionContract];

	/// The expected gate decision. `None` accepts any decision.
	fn expected_gate_decision(&self) -> Option<TransitStatus> {
		None
	}

	/// Whether this spec constrains a task set the schedulability analysis
	/// can refute.
	#[cfg(feature = "testing-timing")]
	fn constrains_schedule(&self) -> bool {
		false
	}

	/// Whether this spec can reject a trace on anything but its mode.
	///
	/// A spec that names no assertion, no gate decision, no required event,
	/// and no task set constrains only the execution mode, which every
	/// completed run satisfies. A scenario built from it cannot fail.
	fn can_reject(&self) -> bool {
		if !self.required_assertions().is_empty() || self.expected_gate_decision().is_some() {
			return true;
		}

		#[cfg(feature = "instrument")]
		if !self.required_events().is_empty() {
			return true;
		}

		#[cfg(feature = "testing-timing")]
		if self.constrains_schedule() {
			return true;
		}

		false
	}

	/// Validates the response with custom logic. The default accepts any frame.
	fn validate_response(&self, _frame: &Frame) -> bool {
		true
	}

	/// Validates the trace with custom logic. The default accepts every trace.
	fn validate_trace(&self, _trace: &ConsumedTrace) -> Result<(), SpecViolation> {
		Ok(())
	}

	/// Verifies a captured trace against the spec contract.
	///
	/// `execution` is what the scenario body returned, which is the one
	/// source of the run's error mode.
	///
	/// The verification runs these checks in order:
	/// 1. The execution mode matches the spec.
	/// 2. The gate decision matches, when the spec constrains it.
	/// 3. Every assertion contract holds.
	/// 4. The required events occur in order, under the `instrument` feature.
	/// 5. The custom response validation passes.
	/// 6. The custom trace validation passes.
	fn verify(&self, trace: &ConsumedTrace, execution: &Result<(), TightBeamError>) -> Result<(), SpecViolation> {
		// 1. Verify the execution mode.
		let actual_mode = ExecutionMode::of(execution, trace);
		if actual_mode != self.mode() {
			return Err(SpecViolation::ModeMismatch(ReceivedExpectedError {
				received: actual_mode,
				expected: self.mode(),
			}));
		}

		// 2. Verify the gate decision when the spec constrains it.
		if let Some(expected_decision) = self.expected_gate_decision() {
			if trace.gate_decision != Some(expected_decision) {
				return Err(SpecViolation::GateDecisionMismatch(GateDecisionMismatch {
					expected: expected_decision,
					actual: trace.gate_decision,
				}));
			}
		}

		// 3. Verify every assertion contract.
		for contract in self.required_assertions() {
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

		// 4. Verify the required event order under the `instrument` feature.
		#[cfg(feature = "instrument")]
		{
			let required_kinds = self.required_events();
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

		// 5. Run the custom response validation.
		if let Some(ref response) = trace.response {
			if !self.validate_response(response) {
				return Err(SpecViolation::ResponseValidationFailed);
			}
		}

		// 6. Run the custom trace validation.
		self.validate_trace(trace)?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use core::error::Error;

	use super::TBSpec;
	use crate::error::TightBeamError;
	use crate::testing::assertions::{Assertion, AssertionLabel};
	use crate::testing::specs::SpecViolation;
	use crate::trace::{ConsumedTrace, IntoEventLabel};
	use crate::urn::Urn;
	use crate::{exactly, tb_assert_spec};

	const STEP: Urn<'static> = crate::urn!("test", "event:assert/step");

	tb_assert_spec! {
		pub OneStepSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(STEP, exactly!(1))
			]
		}
	}

	/// A trace that records `STEP` `count` times.
	fn steps(count: usize) -> ConsumedTrace {
		let mut trace = ConsumedTrace::new();
		let label = AssertionLabel::Custom(STEP.into_label());
		let recorded = (0..count).map(|seq| Assertion::new(seq, label.clone(), Vec::new(), None));

		trace.assertions.extend(recorded);

		trace
	}

	#[test]
	fn a_run_that_meets_its_spec_verifies() -> Result<(), Box<dyn Error>> {
		let trace = steps(1);
		let verdict = OneStepSpec::latest().verify(&trace, &Ok(()));
		assert_eq!(verdict, Ok(()));
		Ok(())
	}

	#[test]
	fn a_run_in_another_mode_is_refused() -> Result<(), Box<dyn Error>> {
		let trace = steps(1);
		let verdict = OneStepSpec::latest().verify(&trace, &Err(TightBeamError::RecvTimeoutError));
		assert!(matches!(verdict, Err(SpecViolation::ModeMismatch(_))));
		Ok(())
	}

	#[test]
	fn a_run_that_misses_an_assertion_is_refused() -> Result<(), Box<dyn Error>> {
		let trace = steps(0);
		let verdict = OneStepSpec::latest().verify(&trace, &Ok(()));
		assert!(matches!(verdict, Err(SpecViolation::AssertionViolation(_))));
		Ok(())
	}
}
