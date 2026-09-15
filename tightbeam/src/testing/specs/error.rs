//! Spec verification error types

use core::fmt::{Display, Formatter};

use crate::error::ReceivedExpectedError;
use crate::testing::assertions::AssertionLabel;
use crate::testing::specs::lts::CspViolation;
use crate::testing::specs::Layer;
use crate::trace::ExecutionMode;

#[cfg(feature = "policy")]
use crate::policy::TransitStatus;
#[cfg(feature = "testing-timing")]
use crate::testing::schedulability::{SchedulabilityError, SchedulabilityResult};
use crate::Errorizable;

/// Gate decision mismatch details
#[derive(Clone, Debug, PartialEq)]
pub struct GateDecisionMismatch {
	pub expected: TransitStatus,
	pub actual: Option<TransitStatus>,
}

/// Assertion contract violation details
#[derive(Clone, Debug, PartialEq)]
pub struct AssertionViolationDetail {
	pub label: AssertionLabel,
	pub tags: Option<Vec<&'static str>>,
	pub expected: String,
	pub actual: usize,
}

/// Event ordering violation details
#[derive(Clone, Debug, PartialEq)]
pub struct EventOrderViolationDetail {
	pub expected_kind: crate::utils::urn::Urn<'static>,
	pub position: usize,
}

/// Event count mismatch details
#[derive(Clone, Debug, PartialEq)]
pub struct EventCountMismatchDetail {
	pub kind: crate::utils::urn::Urn<'static>,
	pub expected: usize,
	pub actual: usize,
}

/// Spec violation error type
#[derive(Clone, Debug, PartialEq, Errorizable)]
pub enum SpecViolation {
	/// The scenario body itself returned an error, carrying its rendering
	#[error("Execution failed: {0}")]
	ExecutionFailed(String),
	/// Response assertion mismatch
	#[error("Response present but spec forbids it")]
	ResponseUnexpectedPresence,
	#[error("Response absent but spec requires it")]
	ResponseUnexpectedAbsence,
	#[error("Response validation failed")]
	ResponseValidationFailed,
	/// Execution mode mismatch
	#[error("Execution mode mismatch: {0}")]
	ModeMismatch(ReceivedExpectedError<ExecutionMode, ExecutionMode>),
	/// Gate decision mismatch
	#[error("Gate decision mismatch: {0:?}")]
	GateDecisionMismatch(GateDecisionMismatch),
	/// Assertion contract violated
	#[error("Assertion contract violated: {0:?}")]
	AssertionViolation(AssertionViolationDetail),
	/// Event ordering violation (instrumentation)
	#[error("Event order violation: {0:?}")]
	EventOrderViolation(EventOrderViolationDetail),
	/// Event count mismatch
	#[error("Event count mismatch: {0:?}")]
	EventCountMismatch(EventCountMismatchDetail),
	/// CSP process validation failed (Layer 2)
	#[error("CSP process violation: {0:?}")]
	CspProcessViolation(Vec<CspViolation>),
	/// Refinement checking rejected the scenario (Layer 3)
	///
	/// The witness for each failed check is on the verdict itself, reachable
	/// through [`ScenarioVerdict::fdr`](crate::testing::ScenarioVerdict::fdr).
	#[error("Refinement check failed")]
	RefinementViolation,
	/// Refinement checking did not conclude (Layer 3)
	///
	/// Exploration stopped on a bound or a timeout, so the layer neither
	/// refuted the run nor cleared it. The bounds are on the verdict itself,
	/// reachable through
	/// [`ScenarioVerdict::fdr`](crate::testing::ScenarioVerdict::fdr).
	#[error("Refinement check did not conclude within its exploration bounds")]
	RefinementInconclusive,
	/// A layer the scenario expected a violation from accepted the run
	#[error("Expected a violation from {0:?}, which accepted the run")]
	ExpectationUnmet(Layer),
	/// Schedulability violation (analysis failed)
	#[cfg(feature = "testing-timing")]
	#[error("Schedulability violation: {0:?}")]
	SchedulabilityViolation(SchedulabilityResult),
	/// Schedulability analysis error (couldn't perform analysis)
	#[cfg(feature = "testing-timing")]
	#[error("Schedulability analysis error: {0}")]
	#[from]
	SchedulabilityError(SchedulabilityError),
}

/// Every layer that rejected one scenario.
///
/// A value of this type exists only where at least one layer rejected the
/// run, so a caller that holds one knows the scenario failed and can read
/// each rejection in layer order through [`Violations::iter`].
#[derive(Clone, Debug, PartialEq)]
pub struct Violations {
	found: Vec<SpecViolation>,
}

impl Violations {
	/// Takes the rejections a grading collected, when it collected any.
	///
	/// `None` reports that every layer accepted the run, which is what keeps
	/// a `Violations` non-empty by construction.
	pub(crate) fn collected(found: impl IntoIterator<Item = SpecViolation>) -> Option<Self> {
		let found: Vec<SpecViolation> = found.into_iter().collect();
		if found.is_empty() {
			return None;
		}

		Some(Self { found })
	}

	/// Every rejection, in layer order.
	pub fn iter(&self) -> impl Iterator<Item = &SpecViolation> {
		self.found.iter()
	}
}

impl Display for Violations {
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		for (position, violation) in self.found.iter().enumerate() {
			if position > 0 {
				write!(f, "; ")?;
			}

			write!(f, "{violation}")?;
		}

		Ok(())
	}
}
