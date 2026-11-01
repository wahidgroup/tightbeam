//! An outside crate writes a [`TBSpec`] with its own assertion order and
//! response contract, and [`TBSpec::verify`] checks traces against it.

use tightbeam::testing::assertions::AssertionContract;
use tightbeam::testing::specs::{
	AssertionOrderContract, EventOrderViolationDetail, ResponseContract, SpecViolation, TBSpec,
};
use tightbeam::testing::TestFrame;
use tightbeam::trace::{ConsumedTrace, ExecutionMode, Presence};
use tightbeam::urn::Urn;
use tightbeam::Frame;

use super::consumed_trace_of;

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
	let mut trace = consumed_trace_of([first, second]);
	trace.record_accepted(TestFrame::v0(None, Some("request")), response);
	trace
}

/// The response that the client of a run receives.
fn response() -> Frame {
	TestFrame::v0(None, Some("response"))
}

/// The verdict of the outside spec on a trace that records `CLOSE` before
/// `OPEN`: the first label out of order, at its position.
fn out_of_order() -> Result<(), SpecViolation> {
	let detail = EventOrderViolationDetail { expected_kind: CLOSE, position: 1 };
	Err(SpecViolation::AssertionOrderViolation(detail))
}

// The outside spec passes a trace that records its labels in its order and
// gets a response, and refuses each trace that breaks its order or its
// response contract.
tightbeam::tb_cases! {
	fn the_outside_spec_judges_a_trace(
		(first, second, response, verdict): (Urn<'static>, Urn<'static>, Option<Frame>, Result<(), SpecViolation>)
	) {
		let trace = trace_of(first, second, response);
		let judged = OpensThenCloses::new().verify(&trace, &Ok(()));
		assert_eq!(judged, verdict);
	}
	cases {
		/// A trace that meets the outside spec passes.
		that_meets_it => (OPEN, CLOSE, Some(response()), Ok(())),
		/// A trace out of the outside order is refused at its first label.
		out_of_its_order => (CLOSE, OPEN, Some(response()), out_of_order()),
		/// A run with no response breaks the outside response contract.
		with_no_response => (OPEN, CLOSE, None, Err(SpecViolation::ResponseUnexpectedAbsence)),
	}
}
