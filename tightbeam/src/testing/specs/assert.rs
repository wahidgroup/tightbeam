//! The contracts of spec-driven testing.
//!
//! The [`TBSpec`] trait holds the verification algorithm of spec-driven CBVOC
//! testing. A spec describes the expected behavior declaratively, and the
//! framework verifies each trace against it.

use super::error::{AssertionViolationDetail, EventOrderViolationDetail, GateDecisionMismatch, SpecViolation};
use crate::error::{ReceivedExpectedError, TightBeamError};
use crate::testing::assertions::AssertionContract;
use crate::trace::{AssertionLabel, ConsumedTrace, ExecutionMode, IntoEventLabel, Presence};
use crate::urn::Urn;
use crate::Frame;

#[cfg(feature = "instrument")]
use super::error::EventCountMismatchDetail;
#[cfg(feature = "policy")]
use crate::policy::TransitStatus;
#[cfg(feature = "instrument")]
use crate::testing::macros::Cardinality;
#[cfg(feature = "instrument")]
use crate::trace::EventRecordTruncated;

/// A spec, which declares the expected behavior of a test.
///
/// An implementor declares:
/// - The execution mode: accept, reject, or error.
/// - The instrumentation events that the trace must record in order.
/// - The required count of each event.
/// - The required assertion contracts, and the order of their labels.
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

	/// The counts that the instrumentation events of the trace must meet,
	/// under the `instrument` feature.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::events;
	/// use tightbeam::testing::specs::TBSpec;
	/// use tightbeam::{exactly, tb_assert_spec};
	///
	/// tb_assert_spec! {
	///     pub AcceptsOnce,
	///     V(1,0,0): {
	///         mode: Accept,
	///         assertions: [],
	///         event_counts: [ (events::GATE_ACCEPT, exactly!(1)) ]
	///     }
	/// }
	///
	/// let counts = AcceptsOnce::latest().required_event_counts();
	/// assert_eq!(counts.len(), 1);
	/// assert_eq!(counts[0].kind, events::GATE_ACCEPT);
	/// ```
	#[cfg(feature = "instrument")]
	fn required_event_counts(&self) -> &[EventCountContract] {
		&[]
	}

	/// The assertion contracts that the trace must meet, each with its
	/// cardinality.
	fn required_assertions(&self) -> &[AssertionContract];

	/// The assertion labels that the trace must record in this order. Other
	/// assertions may come between them.
	///
	/// The default holds no label, so it admits every trace.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::exactly;
	/// use tightbeam::testing::macros::AssertSpecBuilder;
	/// use tightbeam::testing::specs::TBSpec;
	/// use tightbeam::trace::ExecutionMode;
	/// use tightbeam::urn::Urn;
	///
	/// const OPEN: Urn<'static> = tightbeam::urn!("doc", "event:order/open");
	/// const CLOSE: Urn<'static> = tightbeam::urn!("doc", "event:order/close");
	///
	/// let builder = AssertSpecBuilder::new("OpensFirst", ExecutionMode::Accept);
	/// let builder = builder.assertion(OPEN, Vec::new(), exactly!(1))?;
	/// let builder = builder.assertion(CLOSE, Vec::new(), exactly!(1))?;
	/// let spec = builder.ordering([OPEN, CLOSE])?.build();
	///
	/// let order: Vec<_> = spec.required_assertion_order().urns().collect();
	/// assert_eq!(order, [&OPEN, &CLOSE]);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	fn required_assertion_order(&self) -> &AssertionOrderContract {
		&UNORDERED
	}

	/// The expected gate decision. `None` accepts any decision.
	fn expected_gate_decision(&self) -> Option<TransitStatus> {
		None
	}

	/// Whether the run must produce a response. `None` accepts a run with a
	/// response or without one.
	///
	/// A response constraint refuses a run that reported no exchange
	/// ([`SpecViolation::ResponseUnreported`]).
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::tb_assert_spec;
	/// use tightbeam::testing::specs::{ResponseContract, TBSpec};
	/// use tightbeam::trace::Presence;
	///
	/// tb_assert_spec! {
	///     pub Replies,
	///     V(1,0,0): {
	///         mode: Accept,
	///         response: Present,
	///         assertions: []
	///     }
	/// }
	///
	/// assert_eq!(Replies::latest().expected_response(), Some(ResponseContract::new(Presence::Present)));
	/// ```
	fn expected_response(&self) -> Option<ResponseContract> {
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
	/// A spec that constrains only the execution mode passes every completed
	/// run. Each of these constraints counts:
	///
	/// - An assertion contract, or an assertion order.
	/// - A gate decision.
	/// - A required event, or an event count, under the `instrument` feature.
	/// - A task set, under the `testing-timing` feature.
	///
	/// A response constraint stays off the list, because the client closure of
	/// a scenario reports the exchange that it reads.
	fn can_reject(&self) -> bool {
		if !self.required_assertions().is_empty()
			|| !self.required_assertion_order().is_empty()
			|| self.expected_gate_decision().is_some()
		{
			return true;
		}

		#[cfg(feature = "instrument")]
		if !self.required_events().is_empty() || !self.required_event_counts().is_empty() {
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
	/// `execution` is what the scenario body returned, the one source of the
	/// run's error mode.
	///
	/// The verification runs these checks in order:
	/// 1. The execution mode matches the spec.
	/// 2. The gate decision matches, when the spec constrains it.
	/// 3. Every assertion contract holds.
	/// 4. The ordered assertion labels occur in their order.
	/// 5. The required events occur in order, under the `instrument` feature.
	/// 6. Every event count holds, under the `instrument` feature.
	/// 7. The response is present or absent, when the spec constrains it.
	/// 8. The custom response validation passes.
	/// 9. The custom trace validation passes.
	///
	/// # Errors
	///
	/// - [`SpecViolation::ModeMismatch`] -- the run ended in another execution mode.
	/// - [`SpecViolation::GateDecisionMismatch`] -- the gate decided otherwise.
	/// - [`SpecViolation::AssertionViolation`] -- the trace breaks an assertion contract.
	/// - [`SpecViolation::AssertionOrderViolation`] -- the trace lacks an ordered label in its order.
	/// - [`SpecViolation::EventOrderViolation`] -- the trace lacks a required event in its order.
	/// - [`SpecViolation::EventRecordTruncated`] -- the spec counts events, and the record misses events.
	/// - [`SpecViolation::EventCountMismatch`] -- the count of an event falls outside its cardinality.
	/// - [`SpecViolation::ResponseUnreported`] -- the spec constrains the response of a run with no exchange.
	/// - [`SpecViolation::ResponseUnexpectedAbsence`] -- the spec requires a response that the trace lacks.
	/// - [`SpecViolation::ResponseUnexpectedPresence`] -- the spec forbids the response that the trace holds.
	/// - [`SpecViolation::ResponseValidationFailed`] -- the response fails [`Self::validate_response`].
	/// - The error of [`Self::validate_trace`].
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
			if !contract.is_satisfied_by(trace.assertions()) {
				let actual_count = trace.count_assertions(&contract.label, contract.tag_filter.as_deref());
				return Err(SpecViolation::AssertionViolation(AssertionViolationDetail {
					label: contract.label.clone(),
					tags: contract.tag_filter.clone(),
					expected: contract.cardinality.describe(),
					actual: actual_count,
				}));
			}
		}

		// 4. Verify the required assertion order.
		self.required_assertion_order().check(trace)?;

		// 5. Verify the required event order under the `instrument` feature.
		#[cfg(feature = "instrument")]
		{
			let required_kinds = self.required_events();
			let missing =
				first_missing_in_order(required_kinds, trace.instrument_events(), |event, kind| event.urn == *kind);
			if let Some((position, expected)) = missing {
				let detail = EventOrderViolationDetail { expected_kind: expected.clone(), position };
				return Err(SpecViolation::EventOrderViolation(detail));
			}
		}

		// 6. Verify every event count under the `instrument` feature.
		#[cfg(feature = "instrument")]
		for contract in self.required_event_counts() {
			contract.check(trace)?;
		}

		// 7. Verify the response presence when the spec constrains it.
		if let Some(response) = self.expected_response() {
			response.check(trace)?;
		}

		// 8. Run the custom response validation.
		if let Some(response) = trace.response() {
			if !self.validate_response(response) {
				return Err(SpecViolation::ResponseValidationFailed);
			}
		}

		// 9. Run the custom trace validation.
		self.validate_trace(trace)?;

		Ok(())
	}
}

/// The first item of `required` that `recorded` lacks in order, with its index
/// among `required`, or `None` when `recorded` holds every one in order.
///
/// `matches` decides whether a recorded item is the one the order waits for.
/// Other recorded items may come between two of them.
fn first_missing_in_order<T, R>(
	required: &[R],
	recorded: impl IntoIterator<Item = T>,
	matches: impl Fn(&T, &R) -> bool,
) -> Option<(usize, &R)> {
	let mut waiting = required.iter().enumerate().peekable();
	for item in recorded {
		if waiting.peek().is_some_and(|(_, wanted)| matches(&item, wanted)) {
			waiting.next();
		}
	}

	waiting.next()
}

/// The order in which a spec requires the trace to record its assertion
/// labels.
///
/// The contract converts each URN to its [`AssertionLabel`] once, when it
/// takes the URN, so a check compares the labels in place. Other assertions
/// may come between two ordered labels.
///
/// # Examples
///
/// ```
/// use tightbeam::testing::specs::{AssertionOrderContract, EventOrderViolationDetail, SpecViolation};
/// use tightbeam::trace::{ConsumedTrace, TraceCollector};
/// use tightbeam::urn::Urn;
///
/// const OPEN: Urn<'static> = tightbeam::urn!("doc", "event:order/open");
/// const CLOSE: Urn<'static> = tightbeam::urn!("doc", "event:order/close");
///
/// let collector = TraceCollector::new();
/// collector.event(CLOSE)?;
/// collector.event(OPEN)?;
///
/// let mut trace = ConsumedTrace::new();
/// trace.populate_from_collector(&collector);
///
/// let order: AssertionOrderContract = [OPEN, CLOSE].into_iter().collect();
/// let detail = EventOrderViolationDetail { expected_kind: CLOSE, position: 1 };
/// assert_eq!(order.check(&trace), Err(SpecViolation::AssertionOrderViolation(detail)));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AssertionOrderContract {
	/// Each ordered URN with the label that it converts to, in order.
	labels: Vec<(Urn<'static>, AssertionLabel)>,
}

/// The order contract with no label, which every trace meets: the default of
/// [`TBSpec::required_assertion_order`].
static UNORDERED: AssertionOrderContract = AssertionOrderContract { labels: Vec::new() };

impl AssertionOrderContract {
	/// The URNs of the contract, in the order the trace must record them.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::AssertionOrderContract;
	/// use tightbeam::urn::Urn;
	///
	/// const OPEN: Urn<'static> = tightbeam::urn!("doc", "event:order/open");
	///
	/// let order: AssertionOrderContract = [OPEN].into_iter().collect();
	/// assert_eq!(order.urns().collect::<Vec<_>>(), [&OPEN]);
	/// ```
	pub fn urns(&self) -> impl ExactSizeIterator<Item = &Urn<'static>> {
		self.labels.iter().map(|(urn, _)| urn)
	}

	/// Whether the contract holds no label, so it admits every trace.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::AssertionOrderContract;
	///
	/// assert!(AssertionOrderContract::default().is_empty());
	/// ```
	pub fn is_empty(&self) -> bool {
		self.labels.is_empty()
	}

	/// The text of each label of the contract, in order.
	pub(crate) fn labels(&self) -> impl ExactSizeIterator<Item = &str> {
		self.labels.iter().map(|(_, AssertionLabel::Custom(label))| label.as_ref())
	}

	/// Checks that the assertions of `trace` record each label in its order.
	///
	/// # Errors
	///
	/// - [`SpecViolation::AssertionOrderViolation`] -- the trace lacks an ordered label in its order.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::AssertionOrderContract;
	/// use tightbeam::trace::{ConsumedTrace, TraceCollector};
	/// use tightbeam::urn::Urn;
	///
	/// const OPEN: Urn<'static> = tightbeam::urn!("doc", "event:order/open");
	/// const CLOSE: Urn<'static> = tightbeam::urn!("doc", "event:order/close");
	///
	/// let collector = TraceCollector::new();
	/// collector.event(OPEN)?;
	/// collector.event(CLOSE)?;
	///
	/// let mut trace = ConsumedTrace::new();
	/// trace.populate_from_collector(&collector);
	///
	/// let order: AssertionOrderContract = [OPEN, CLOSE].into_iter().collect();
	/// assert_eq!(order.check(&trace), Ok(()));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn check(&self, trace: &ConsumedTrace) -> Result<(), SpecViolation> {
		let unordered = first_missing_in_order(&self.labels, trace.assertions(), |assertion, (_, label)| {
			assertion.label.matches(label)
		});
		if let Some((position, (expected, _))) = unordered {
			let detail = EventOrderViolationDetail { expected_kind: expected.clone(), position };
			return Err(SpecViolation::AssertionOrderViolation(detail));
		}

		Ok(())
	}
}

impl Extend<Urn<'static>> for AssertionOrderContract {
	fn extend<I: IntoIterator<Item = Urn<'static>>>(&mut self, urns: I) {
		let labelled = urns.into_iter().map(|urn| {
			let label = AssertionLabel::Custom((&urn).into_label());
			(urn, label)
		});
		self.labels.extend(labelled);
	}
}

impl FromIterator<Urn<'static>> for AssertionOrderContract {
	fn from_iter<I: IntoIterator<Item = Urn<'static>>>(urns: I) -> Self {
		let mut contract = Self::default();
		contract.extend(urns);
		contract
	}
}

/// Whether a spec requires the run to produce a response.
///
/// The contract reads the frames that the exchanges of the run report, so a
/// run that reported no exchange meets no response contract.
///
/// # Examples
///
/// ```
/// use tightbeam::testing::specs::{ResponseContract, SpecViolation};
/// use tightbeam::testing::TestFrame;
/// use tightbeam::trace::{ConsumedTrace, Presence};
///
/// let silent = ResponseContract::new(Presence::Absent);
/// let mut trace = ConsumedTrace::new();
/// assert_eq!(silent.check(&trace), Err(SpecViolation::ResponseUnreported));
///
/// trace.record_rejected(TestFrame::v0(None, Some("request")));
/// assert_eq!(silent.check(&trace), Ok(()));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseContract {
	/// Whether the client of the run must receive a response.
	pub presence: Presence,
}

impl ResponseContract {
	/// The contract that the client of the run receives a response for
	/// [`Presence::Present`], or none for [`Presence::Absent`].
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::ResponseContract;
	/// use tightbeam::trace::Presence;
	///
	/// assert_eq!(ResponseContract::new(Presence::Present).presence, Presence::Present);
	/// ```
	pub const fn new(presence: Presence) -> Self {
		Self { presence }
	}

	/// Checks the response presence of `trace` against the contract.
	///
	/// # Errors
	///
	/// - [`SpecViolation::ResponseUnreported`] -- the run reported no exchange.
	/// - [`SpecViolation::ResponseUnexpectedAbsence`] -- the trace lacks the required response.
	/// - [`SpecViolation::ResponseUnexpectedPresence`] -- the trace holds a forbidden response.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::{ResponseContract, SpecViolation};
	/// use tightbeam::testing::TestFrame;
	/// use tightbeam::trace::{ConsumedTrace, Presence};
	///
	/// let mut trace = ConsumedTrace::new();
	/// trace.record_accepted(TestFrame::v0(None, Some("request")), None);
	///
	/// let replies = ResponseContract::new(Presence::Present);
	/// assert_eq!(replies.check(&trace), Err(SpecViolation::ResponseUnexpectedAbsence));
	/// ```
	pub fn check(&self, trace: &ConsumedTrace) -> Result<(), SpecViolation> {
		let actual = trace.response_presence().ok_or(SpecViolation::ResponseUnreported)?;
		match (self.presence, actual) {
			(Presence::Present, Presence::Absent) => Err(SpecViolation::ResponseUnexpectedAbsence),
			(Presence::Absent, Presence::Present) => Err(SpecViolation::ResponseUnexpectedPresence),
			(Presence::Present, Presence::Present) | (Presence::Absent, Presence::Absent) => Ok(()),
		}
	}
}

/// A count that a spec places on one instrumentation event.
///
/// The contract counts the events of its kind in the instrumentation record
/// of a trace: the events a run emits through the event API, such as
/// [`TraceCollector::emit_event`].
///
/// [`TraceCollector::emit_event`]: crate::trace::TraceCollector::emit_event
#[cfg(feature = "instrument")]
#[derive(Clone, Debug, PartialEq)]
pub struct EventCountContract {
	/// The event URN that the contract counts.
	pub kind: Urn<'static>,
	/// The count of `kind` events that satisfies the contract.
	pub cardinality: Cardinality,
}

#[cfg(feature = "instrument")]
impl EventCountContract {
	/// The contract that the trace records `kind` a number of times that
	/// `cardinality` admits.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::events;
	/// use tightbeam::testing::specs::EventCountContract;
	/// use tightbeam::{absent, exactly};
	///
	/// let never = EventCountContract::new(events::GATE_REJECT, absent!());
	/// assert_eq!(never.kind, events::GATE_REJECT);
	/// assert_ne!(never.cardinality, exactly!(1));
	/// ```
	pub const fn new(kind: Urn<'static>, cardinality: Cardinality) -> Self {
		Self { kind, cardinality }
	}

	/// Checks the count of `kind` in the instrumentation record of `trace`.
	///
	/// A record that misses events ([`ConsumedTrace::is_complete`]) holds fewer
	/// events than the run emitted, so it decides no count.
	///
	/// # Errors
	///
	/// - [`SpecViolation::EventRecordTruncated`] -- the record of the trace misses events.
	/// - [`SpecViolation::EventCountMismatch`] -- the count of `kind` falls outside `cardinality`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::exactly;
	/// use tightbeam::instrumentation::{events, TbInstrumentationConfig};
	/// use tightbeam::testing::specs::{EventCountContract, SpecViolation};
	/// use tightbeam::trace::{ConsumedTrace, TraceCollector, TraceConfig};
	///
	/// let config = TraceConfig::with_instrumentation(TbInstrumentationConfig::default());
	/// let collector = TraceCollector::from(config);
	/// collector.emit(events::GATE_ACCEPT, "Ok");
	///
	/// let mut trace = ConsumedTrace::new();
	/// trace.populate_from_collector(&collector);
	///
	/// let once = EventCountContract::new(events::GATE_ACCEPT, exactly!(1));
	/// let twice = EventCountContract::new(events::GATE_ACCEPT, exactly!(2));
	/// assert_eq!(once.check(&trace), Ok(()));
	/// assert!(matches!(twice.check(&trace), Err(SpecViolation::EventCountMismatch(_))));
	/// ```
	pub fn check(&self, trace: &ConsumedTrace) -> Result<(), SpecViolation> {
		let counted = trace.count_event_urn(self.kind.clone());
		let actual = counted.map_err(|EventRecordTruncated| SpecViolation::EventRecordTruncated)?;
		if self.cardinality.is_satisfied_by(actual) {
			return Ok(());
		}

		Err(SpecViolation::EventCountMismatch(EventCountMismatchDetail {
			kind: self.kind.clone(),
			expected: self.cardinality,
			actual,
		}))
	}
}

#[cfg(test)]
mod tests {
	use super::TBSpec;
	use crate::error::{ReceivedExpectedError, TightBeamError};
	use crate::testing::macros::{AssertSpecBuilder, BuiltAssertSpec};
	use crate::testing::specs::{AssertionViolationDetail, EventOrderViolationDetail, SpecViolation};
	use crate::testing::TestFrame;
	use crate::trace::{ConsumedTrace, ExecutionMode};
	use crate::urn::Urn;
	use crate::{exactly, tb_assert_spec};

	#[cfg(feature = "instrument")]
	use crate::instrumentation::{events, TbInstrumentationConfig};
	#[cfg(feature = "instrument")]
	use crate::testing::fixtures::TestTrace;
	#[cfg(feature = "instrument")]
	use crate::testing::specs::EventCountMismatchDetail;

	const STEP: Urn<'static> = crate::urn!("test", "event:assert/step");
	const FIRST: Urn<'static> = crate::urn!("test", "event:assert/first");
	const SECOND: Urn<'static> = crate::urn!("test", "event:assert/second");

	tb_assert_spec! {
		pub OneStepSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(STEP, exactly!(1))
			]
		}
	}

	tb_assert_spec! {
		pub RepliesSpec,
		V(1,0,0): {
			mode: Accept,
			response: Present,
			assertions: []
		}
	}

	tb_assert_spec! {
		pub SilentSpec,
		V(1,0,0): {
			mode: Accept,
			response: Absent,
			assertions: []
		}
	}

	#[cfg(feature = "instrument")]
	tb_assert_spec! {
		pub RejectsAfterAcceptSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [],
			events: [events::GATE_ACCEPT, events::GATE_REJECT]
		}
	}

	#[cfg(feature = "instrument")]
	tb_assert_spec! {
		pub AcceptsOnceSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [],
			event_counts: [
				(events::GATE_ACCEPT, exactly!(1))
			]
		}
	}

	/// A trace that records `STEP` `count` times.
	fn steps(count: usize) -> ConsumedTrace {
		ConsumedTrace::recording(vec![STEP; count])
	}

	/// A spec that requires `FIRST` and then `SECOND`, once each.
	fn first_then_second() -> BuiltAssertSpec {
		let builder = AssertSpecBuilder::new("FirstThenSecond", ExecutionMode::Accept);
		let builder = builder.assertion(FIRST, Vec::new(), exactly!(1)).expect("FIRST is a new label");
		let builder = builder
			.assertion(SECOND, Vec::new(), exactly!(1))
			.expect("SECOND is a new label");
		builder.ordering([FIRST, SECOND]).expect("the spec holds both labels").build()
	}

	/// A trace whose run reported one accepted request, answered with a
	/// response frame when `answered` holds.
	fn exchanged(answered: bool) -> ConsumedTrace {
		let request = TestFrame::v0(None, Some("request"));
		let response = answered.then(|| TestFrame::v0(None, Some("reply")));

		let mut trace = ConsumedTrace::new();
		trace.record_accepted(request, response);
		trace
	}

	/// A trace whose instrumentation record holds `count` gate acceptances,
	/// drained from a sink that holds `max_events` events.
	#[cfg(feature = "instrument")]
	fn accepted(count: usize, max_events: u32) -> ConsumedTrace {
		let collector = TestTrace::with_config(TbInstrumentationConfig { max_events, ..Default::default() });
		for _ in 0..count {
			collector.emit(events::GATE_ACCEPT, "Ok");
		}

		ConsumedTrace::drained_from(&collector)
	}

	// A spec judges a run by its assertions, their order, its response, and
	// its instrumentation events.
	crate::tb_cases! {
		fn a_spec_judges_a_run((spec, trace, verdict): (&BuiltAssertSpec, ConsumedTrace, Result<(), SpecViolation>)) {
			let judged = spec.verify(&trace, &Ok(()));
			assert_eq!(judged, verdict);
		}

		cases {
			that_meets_its_assertions => (OneStepSpec::latest(), steps(1), Ok(())),
			that_records_its_ordered_labels_in_order => (
				&first_then_second(),
				ConsumedTrace::recording([FIRST, SECOND]),
				Ok(()),
			),
			that_records_its_ordered_labels_out_of_order => (
				&first_then_second(),
				ConsumedTrace::recording([SECOND, FIRST]),
				Err(SpecViolation::AssertionOrderViolation(EventOrderViolationDetail {
					expected_kind: SECOND,
					position: 1,
				})),
			),
			with_the_response_its_spec_requires => (RepliesSpec::latest(), exchanged(true), Ok(())),
			without_the_response_its_spec_requires => (
				RepliesSpec::latest(),
				exchanged(false),
				Err(SpecViolation::ResponseUnexpectedAbsence),
			),
			with_a_response_its_spec_forbids => (
				SilentSpec::latest(),
				exchanged(true),
				Err(SpecViolation::ResponseUnexpectedPresence),
			),
			/// A run that reports no exchange meets no spec that forbids a
			/// response.
			that_reports_no_exchange_to_a_spec_that_forbids_a_response => (
				SilentSpec::latest(),
				ConsumedTrace::new(),
				Err(SpecViolation::ResponseUnreported),
			),
			/// A run that reports no exchange meets no spec that requires a
			/// response.
			that_reports_no_exchange_to_a_spec_that_requires_a_response => (
				RepliesSpec::latest(),
				ConsumedTrace::new(),
				Err(SpecViolation::ResponseUnreported),
			),
			#[cfg(feature = "instrument")]
			that_meets_its_event_count => (AcceptsOnceSpec::latest(), accepted(1, 1024), Ok(())),
			#[cfg(feature = "instrument")]
			whose_event_count_breaks_its_spec => (
				AcceptsOnceSpec::latest(),
				accepted(2, 1024),
				Err(SpecViolation::EventCountMismatch(EventCountMismatchDetail {
					kind: events::GATE_ACCEPT,
					expected: exactly!(1),
					actual: 2,
				})),
			),
			/// A truncated record decides no event count.
			#[cfg(feature = "instrument")]
			whose_record_is_truncated => (
				AcceptsOnceSpec::latest(),
				accepted(2, 1),
				Err(SpecViolation::EventRecordTruncated),
			),
			#[cfg(feature = "instrument")]
			that_lacks_a_required_event_in_order => (
				RejectsAfterAcceptSpec::latest(),
				accepted(1, 1024),
				Err(SpecViolation::EventOrderViolation(EventOrderViolationDetail {
					expected_kind: events::GATE_REJECT,
					position: 1,
				})),
			),
		}
	}

	/// A run in another mode than the spec expects is refused.
	#[test]
	fn a_run_in_another_mode_is_refused() {
		let trace = steps(1);
		let verdict = OneStepSpec::latest().verify(&trace, &Err(TightBeamError::RecvTimeoutError));
		let modes = ReceivedExpectedError { received: ExecutionMode::Error, expected: ExecutionMode::Accept };
		assert_eq!(verdict, Err(SpecViolation::ModeMismatch(modes)));
	}

	/// A run that misses an assertion of its spec is refused.
	#[test]
	fn a_run_that_misses_an_assertion_is_refused() {
		let trace = steps(0);
		let verdict = OneStepSpec::latest().verify(&trace, &Ok(()));
		assert!(matches!(
			verdict,
			Err(SpecViolation::AssertionViolation(AssertionViolationDetail { actual: 0, .. }))
		));
	}

	// A spec can reject a run when it counts an event, and it cannot when it
	// constrains the response alone.
	crate::tb_cases! {
		fn whether_a_spec_can_reject((spec, can_reject): (&BuiltAssertSpec, bool)) {
			let decided = spec.can_reject();
			assert_eq!(decided, can_reject);
		}

		cases {
			that_constrains_only_the_response => (SilentSpec::latest(), false),
			#[cfg(feature = "instrument")]
			that_counts_only_an_event => (AcceptsOnceSpec::latest(), true),
		}
	}
}
