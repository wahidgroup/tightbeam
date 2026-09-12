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
#[cfg(feature = "derive")]
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
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "derive", derive(Errorizable))]
pub enum SpecViolation {
	/// The scenario body itself returned an error, carrying its rendering
	#[cfg_attr(feature = "derive", error("Execution failed: {0}"))]
	ExecutionFailed(String),
	/// Response assertion mismatch
	#[cfg_attr(feature = "derive", error("Response present but spec forbids it"))]
	ResponseUnexpectedPresence,
	#[cfg_attr(feature = "derive", error("Response absent but spec requires it"))]
	ResponseUnexpectedAbsence,
	#[cfg_attr(feature = "derive", error("Response validation failed"))]
	ResponseValidationFailed,
	/// Execution mode mismatch
	#[cfg_attr(feature = "derive", error("Execution mode mismatch: {0}"))]
	ModeMismatch(ReceivedExpectedError<ExecutionMode, ExecutionMode>),
	/// Gate decision mismatch
	#[cfg_attr(feature = "derive", error("Gate decision mismatch: {0:?}"))]
	GateDecisionMismatch(GateDecisionMismatch),
	/// Assertion contract violated
	#[cfg_attr(feature = "derive", error("Assertion contract violated: {0:?}"))]
	AssertionViolation(AssertionViolationDetail),
	/// Event ordering violation (instrumentation)
	#[cfg_attr(feature = "derive", error("Event order violation: {0:?}"))]
	EventOrderViolation(EventOrderViolationDetail),
	/// Event count mismatch
	#[cfg_attr(feature = "derive", error("Event count mismatch: {0:?}"))]
	EventCountMismatch(EventCountMismatchDetail),
	/// CSP process validation failed (Layer 2)
	#[cfg_attr(feature = "derive", error("CSP process violation: {0:?}"))]
	CspProcessViolation(Vec<CspViolation>),
	/// Refinement checking rejected the scenario (Layer 3)
	///
	/// The witness for each failed check is on the verdict itself, reachable
	/// through [`ScenarioVerdict::fdr`](crate::testing::ScenarioVerdict::fdr).
	#[cfg_attr(feature = "derive", error("Refinement check failed"))]
	RefinementViolation,
	/// Refinement checking did not conclude (Layer 3)
	///
	/// Exploration stopped on a bound or a timeout, so the layer neither
	/// refuted the run nor cleared it. The bounds are on the verdict itself,
	/// reachable through
	/// [`ScenarioVerdict::fdr`](crate::testing::ScenarioVerdict::fdr).
	#[cfg_attr(
		feature = "derive",
		error("Refinement check did not conclude within its exploration bounds")
	)]
	RefinementInconclusive,
	/// A layer the scenario expected a violation from accepted the run
	#[cfg_attr(
		feature = "derive",
		error("Expected a violation from {0:?}, which accepted the run")
	)]
	ExpectationUnmet(Layer),
	/// Schedulability violation (analysis failed)
	#[cfg(feature = "testing-timing")]
	#[cfg_attr(feature = "derive", error("Schedulability violation: {0:?}"))]
	SchedulabilityViolation(SchedulabilityResult),
	/// Schedulability analysis error (couldn't perform analysis)
	#[cfg(feature = "testing-timing")]
	#[cfg_attr(feature = "derive", error("Schedulability analysis error: {0}"))]
	#[cfg_attr(feature = "derive", from)]
	SchedulabilityError(SchedulabilityError),
}

#[cfg(not(feature = "derive"))]
impl std::fmt::Display for SpecViolation {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::ExecutionFailed(rendering) => write!(f, "Execution failed: {rendering}"),
			Self::ModeMismatch(err) => write!(f, "Execution mode mismatch: {err}"),
			Self::ResponseUnexpectedPresence => write!(f, "Response present but spec forbids it"),
			Self::ResponseUnexpectedAbsence => write!(f, "Response absent but spec requires it"),
			Self::ResponseValidationFailed => write!(f, "Response validation failed"),
			Self::GateDecisionMismatch(detail) => {
				write!(
					f,
					"Gate decision mismatch: expected {:?}, got {:?}",
					detail.expected, detail.actual
				)
			}
			Self::AssertionViolation(detail) => {
				let tag_desc = if let Some(ref t) = detail.tags {
					format!(" with tags {t:?}")
				} else {
					String::new()
				};
				write!(
					f,
					"Assertion contract violated: {:?}{tag_desc} expected {}, found {}",
					detail.label, detail.expected, detail.actual
				)
			}
			Self::EventOrderViolation(detail) => {
				write!(
					f,
					"Event order violation: expected {:?} at position {}",
					detail.expected_kind, detail.position
				)
			}
			Self::EventCountMismatch(detail) => {
				write!(
					f,
					"Event count mismatch: {:?} expected {}, found {}",
					detail.kind, detail.expected, detail.actual
				)
			}
			Self::CspProcessViolation(violations) => {
				write!(f, "CSP process violation:")?;
				for violation in violations {
					write!(f, "\n  - {violation}")?;
				}
				Ok(())
			}
			Self::RefinementViolation => write!(f, "Refinement check failed"),
			Self::RefinementInconclusive => {
				write!(f, "Refinement check did not conclude within its exploration bounds")
			}
			Self::ExpectationUnmet(layer) => {
				write!(f, "Expected a violation from {layer:?}, which accepted the run")
			}
			#[cfg(feature = "testing-timing")]
			Self::SchedulabilityViolation(result) => {
				use crate::testing::schedulability::SchedulerType;
				let scheduler_name = match result.scheduler {
					SchedulerType::RateMonotonic => "Rate Monotonic",
					SchedulerType::EarliestDeadlineFirst => "Earliest Deadline First",
				};
				write!(
					f,
					"Schedulability violation ({} scheduler): utilization {:.3} exceeds bound {:.3}",
					scheduler_name, result.utilization, result.utilization_bound
				)?;
				if !result.violations.is_empty() {
					write!(f, "\nViolations:")?;
					for v in &result.violations {
						write!(f, "\n  - [{}] {}", v.task_id, v.message)?;
					}
				}
				Ok(())
			}
			#[cfg(feature = "testing-timing")]
			Self::SchedulabilityError(error) => {
				write!(f, "Schedulability analysis error: {}", error)
			}
		}
	}
}

#[cfg(not(feature = "derive"))]
impl std::error::Error for SpecViolation {}

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
	pub(crate) fn collected(found: Vec<SpecViolation>) -> Option<Self> {
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
