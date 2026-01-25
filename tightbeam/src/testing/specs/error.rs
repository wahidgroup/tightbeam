//! Spec verification error types

use crate::error::ReceivedExpectedError;
use crate::testing::assertions::AssertionLabel;
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
#[cfg(feature = "instrument")]
#[derive(Clone, Debug, PartialEq)]
pub struct EventOrderViolationDetail {
	pub expected_kind: crate::utils::urn::Urn<'static>,
	pub position: usize,
}

/// Event count mismatch details
#[cfg(feature = "instrument")]
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
	/// No violation detected (test passed Layer 1)
	#[cfg_attr(feature = "derive", error("No violation - test passed"))]
	None,
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
	#[cfg(feature = "instrument")]
	#[cfg_attr(feature = "derive", error("Event order violation: {0:?}"))]
	EventOrderViolation(EventOrderViolationDetail),
	/// Event count mismatch
	#[cfg(feature = "instrument")]
	#[cfg_attr(feature = "derive", error("Event count mismatch: {0:?}"))]
	EventCountMismatch(EventCountMismatchDetail),
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
			Self::None => write!(f, "No violation - test passed"),
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
			#[cfg(feature = "instrument")]
			Self::EventOrderViolation(detail) => {
				write!(
					f,
					"Event order violation: expected {:?} at position {}",
					detail.expected_kind, detail.position
				)
			}
			#[cfg(feature = "instrument")]
			Self::EventCountMismatch(detail) => {
				write!(
					f,
					"Event count mismatch: {:?} expected {}, found {}",
					detail.kind, detail.expected, detail.actual
				)
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
