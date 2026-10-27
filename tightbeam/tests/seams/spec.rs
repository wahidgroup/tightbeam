//! An outside crate writes a [`TBSpec`] with its own assertion order and
//! response contract, and [`TBSpec::verify`] checks traces against it.

use tightbeam::testing::assertions::AssertionContract;
use tightbeam::testing::specs::{
	AssertionOrderContract, EventOrderViolationDetail, ResponseContract, SpecViolation, TBSpec,
};
use tightbeam::testing::TestFrame;
use tightbeam::trace::{ConsumedTrace, ExecutionMode, Presence, TraceCollector};
use tightbeam::urn::Urn;
use tightbeam::Frame;

/// The label that the outside spec requires first.
const OPEN: Urn<'static> = tightbeam::urn!("outside", "event:spec/open");
/// The label that the outside spec requires after [`OPEN`].
const CLOSE: Urn<'static> = tightbeam::urn!("outside", "event:spec/close");

/// An outside spec that requires [`OPEN`] before [`CLOSE`], and a response.
struct OpensThenCloses {
	/// The order of the two labels, which the spec builds itself.
	order: AssertionOrderContract,
}

impl OpensThenCloses {
	/// The spec, with its order built through `FromIterator`.
	fn new() -> Self {
		Self { order: [OPEN, CLOSE].into_iter().collect() }
	}
}

impl TBSpec for OpensThenCloses {
	fn id(&self) -> &'static str {
		"OpensThenCloses"
	}

	fn mode(&self) -> ExecutionMode {
		ExecutionMode::Accept
	}

	fn required_assertions(&self) -> &[AssertionContract] {
		&[]
	}

	fn required_assertion_order(&self) -> &AssertionOrderContract {
		&self.order
	}

	fn expected_response(&self) -> Option<ResponseContract> {
		Some(ResponseContract::new(Presence::Present))
	}
}

/// The trace of a run that records `first`, then `second`, and gets `response`.
fn trace_of(first: Urn<'static>, second: Urn<'static>, response: Option<Frame>) -> ConsumedTrace {
	let collector = TraceCollector::new();
	let records = "a collector with no fault model records each event";

	collector.event(first).expect(records);
	collector.event(second).expect(records);

	let mut trace = ConsumedTrace::new();
	trace.populate_from_collector(&collector);
	trace.record_accepted(TestFrame::v0(None, Some("request")), response);
	trace
}

/// The response that the client of a run receives.
fn response() -> Frame {
	TestFrame::v0(None, Some("response"))
}

#[test]
fn a_trace_that_meets_the_outside_spec_passes() -> Result<(), SpecViolation> {
	let trace = trace_of(OPEN, CLOSE, Some(response()));
	OpensThenCloses::new().verify(&trace, &Ok(()))
}

#[test]
fn a_trace_out_of_the_outside_order_is_refused() -> Result<(), SpecViolation> {
	let trace = trace_of(CLOSE, OPEN, Some(response()));

	let verdict = OpensThenCloses::new().verify(&trace, &Ok(()));
	let detail = EventOrderViolationDetail { expected_kind: CLOSE, position: 1 };
	assert_eq!(verdict, Err(SpecViolation::AssertionOrderViolation(detail)));
	Ok(())
}

#[test]
fn a_run_with_no_response_breaks_the_outside_response_contract() -> Result<(), SpecViolation> {
	let trace = trace_of(OPEN, CLOSE, None);
	let verdict = OpensThenCloses::new().verify(&trace, &Ok(()));
	assert_eq!(verdict, Err(SpecViolation::ResponseUnexpectedAbsence));
	Ok(())
}
