//! The error types of spec verification.

use core::fmt::{Display, Formatter};

use crate::error::ReceivedExpectedError;
use crate::testing::assertions::AssertionLabel;
use crate::testing::macros::Cardinality;
use crate::testing::specs::lts::CspViolation;
use crate::testing::specs::Layer;
use crate::trace::ExecutionMode;
use crate::Errorizable;

#[cfg(feature = "policy")]
use crate::policy::TransitStatus;
#[cfg(feature = "testing-timing")]
use crate::testing::schedulability::{SchedulabilityError, SchedulabilityResult};

/// The gate decision that a spec expects, and the one the trace recorded.
#[derive(Clone, Debug, PartialEq)]
pub struct GateDecisionMismatch {
	/// The gate decision that the spec expects.
	pub expected: TransitStatus,
	/// The gate decision that the trace recorded, or `None` for no decision.
	pub actual: Option<TransitStatus>,
}

/// The label, tag filter, and cardinality of a broken assertion contract,
/// with the count that the trace holds.
#[derive(Clone, Debug, PartialEq)]
pub struct AssertionViolationDetail {
	/// The label of the broken contract.
	pub label: AssertionLabel,
	/// The tag filter of the contract, or `None` when the contract has none.
	pub tags: Option<Vec<&'static str>>,
	/// The cardinality that the contract requires, as text.
	pub expected: String,
	/// The count of the trace assertions that match the label and the filter.
	pub actual: usize,
}

/// The first required event that the trace lacks in order, and its index
/// among the required events.
#[derive(Clone, Debug, PartialEq)]
pub struct EventOrderViolationDetail {
	/// The first required event that the trace lacks in order.
	pub expected_kind: crate::urn::Urn<'static>,
	/// The index of that event among the required events.
	pub position: usize,
}

/// An event kind, with the cardinality that a spec expects of its count and
/// the actual count.
#[derive(Clone, Debug, PartialEq)]
pub struct EventCountMismatchDetail {
	/// The event kind that the spec counts.
	pub kind: crate::urn::Urn<'static>,
	/// The cardinality that the spec expects of the count.
	pub expected: Cardinality,
	/// The count that the trace holds.
	pub actual: usize,
}

/// The error that the verification of a scenario reports.
#[derive(Clone, Debug, PartialEq, Errorizable)]
pub enum SpecViolation {
	/// The scenario body itself returned an error, and the string renders it.
	#[error("Execution failed: {0}")]
	ExecutionFailed(String),
	/// A spec forbids a response, and the trace holds one.
	#[error("Response present but spec forbids it")]
	ResponseUnexpectedPresence,
	/// A spec requires a response, and the trace holds none.
	#[error("Response absent but spec requires it")]
	ResponseUnexpectedAbsence,
	/// A spec constrains the response, and the run reported no exchange, so
	/// the trace holds no evidence of the response.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::tb_assert_spec;
	/// use tightbeam::testing::specs::{SpecViolation, TBSpec};
	/// use tightbeam::trace::ConsumedTrace;
	///
	/// tb_assert_spec! {
	///     pub Silent,
	///     V(1,0,0): {
	///         mode: Accept,
	///         response: Absent,
	///         assertions: []
	///     }
	/// }
	///
	/// let verdict = Silent::latest().verify(&ConsumedTrace::new(), &Ok(()));
	/// assert_eq!(verdict, Err(SpecViolation::ResponseUnreported));
	/// ```
	#[error("Response unreported: the run reported no exchange, so the spec decides no response")]
	ResponseUnreported,
	/// The response fails the response validation of the spec.
	#[error("Response validation failed")]
	ResponseValidationFailed,
	/// The execution mode of the run differs from the mode the spec names.
	#[error("Execution mode mismatch: {0}")]
	ModeMismatch(ReceivedExpectedError<ExecutionMode, ExecutionMode>),
	/// The gate decision of the run differs from the decision the spec expects.
	#[error("Gate decision mismatch: {0:?}")]
	GateDecisionMismatch(GateDecisionMismatch),
	/// The trace breaks the cardinality of an assertion contract.
	#[error("Assertion contract violated: {0:?}")]
	AssertionViolation(AssertionViolationDetail),
	/// The trace lacks the ordered assertion labels of a spec in their order.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::{EventOrderViolationDetail, SpecViolation};
	///
	/// const CLOSE: tightbeam::urn::Urn<'static> = tightbeam::urn!("doc", "event:order/close");
	///
	/// let detail = EventOrderViolationDetail { expected_kind: CLOSE, position: 1 };
	/// let refused = SpecViolation::AssertionOrderViolation(detail);
	/// assert!(refused.to_string().starts_with("Assertion order violation"));
	/// ```
	#[error("Assertion order violation: {0:?}")]
	AssertionOrderViolation(EventOrderViolationDetail),
	/// The trace lacks the required instrumentation events in their order.
	#[error("Event order violation: {0:?}")]
	EventOrderViolation(EventOrderViolationDetail),
	/// The count of an event kind falls outside the cardinality a spec expects.
	#[error("Event count mismatch: {0:?}")]
	EventCountMismatch(EventCountMismatchDetail),
	/// The spec counts events, and the instrumentation record of the trace
	/// misses events ([`ConsumedTrace::is_complete`]), so it decides no count.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::exactly;
	/// use tightbeam::instrumentation::{events, TbInstrumentationConfig};
	/// use tightbeam::testing::specs::{EventCountContract, SpecViolation};
	/// use tightbeam::trace::{ConsumedTrace, TraceCollector, TraceConfig};
	///
	/// let config = TbInstrumentationConfig { max_events: 1, ..Default::default() };
	/// let collector = TraceCollector::from(TraceConfig::with_instrumentation(config));
	/// collector.emit(events::GATE_ACCEPT, "Ok");
	/// collector.emit(events::GATE_ACCEPT, "Ok");
	///
	/// let mut trace = ConsumedTrace::new();
	/// trace.populate_from_collector(&collector);
	///
	/// let twice = EventCountContract::new(events::GATE_ACCEPT, exactly!(2));
	/// assert_eq!(twice.check(&trace), Err(SpecViolation::EventRecordTruncated));
	/// ```
	///
	/// [`ConsumedTrace::is_complete`]: crate::trace::ConsumedTrace::is_complete
	#[error("Event record truncated: the record misses events, so no event count is decided")]
	EventRecordTruncated,
	/// The trace violates the CSP process of Layer 2.
	#[error("CSP process violation: {0:?}")]
	CspProcessViolation(Vec<CspViolation>),
	/// The refinement check of Layer 3 rejected the scenario.
	///
	/// The witness for each failed check is on the verdict itself, reachable
	/// through [`ScenarioVerdict::fdr`](crate::testing::ScenarioVerdict::fdr).
	#[error("Refinement check failed")]
	RefinementViolation,
	/// The refinement check of Layer 3 stopped before it decided.
	///
	/// Exploration stopped on a bound or a timeout, so the layer neither
	/// refuted the run nor cleared it. The bounds are on the verdict itself
	/// ([`ScenarioVerdict::fdr`](crate::testing::ScenarioVerdict::fdr)).
	#[error("Refinement check did not conclude within its exploration bounds")]
	RefinementInconclusive,
	/// The layer that the scenario expects a violation from accepted the run.
	#[error("Expected a violation from {0:?}, which accepted the run")]
	ExpectationUnmet(Layer),
	/// The schedulability analysis contradicts the assertion of the spec.
	#[cfg(feature = "testing-timing")]
	#[error("Schedulability violation: {0:?}")]
	SchedulabilityViolation(SchedulabilityResult),
	/// The schedulability analysis could not run.
	#[cfg(feature = "testing-timing")]
	#[error("Schedulability analysis error: {0}")]
	#[from]
	SchedulabilityError(SchedulabilityError),
}

/// Every layer that rejected one scenario.
///
/// A value exists only when at least one layer rejected the run, so its holder
/// knows the scenario failed. [`Violations::iter`] reads each rejection in
/// layer order.
#[derive(Clone, Debug, PartialEq)]
pub struct Violations {
	found: Vec<SpecViolation>,
}

impl Violations {
	/// Takes the rejections a grading collected, when it collected any.
	///
	/// `None` reports that every layer accepted the run, so a `Violations` is
	/// never empty.
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

// A grading returns this type as its error, so a caller can carry it with `?`.
impl core::error::Error for Violations {}
