//! The integration tests of job pipeline orchestration under `tb_scenario!`.
//!
//! The tests show:
//! - the URN trace events that each `then_job` step of a traced pipeline emits,
//! - a CSP process spec that checks the state machine, and
//! - L1 assertion specs that count the events.

#![cfg(feature = "testing")]

use tightbeam::task::Pipeline;
use tightbeam::testing::TestMessage;
use tightbeam::{compose, job};
use tightbeam::{Frame, TightBeamError};

#[cfg(feature = "testing-csp")]
use tightbeam::testing::ScenarioConfig;
#[cfg(feature = "testing-csp")]
use tightbeam::urn::Urn;
#[cfg(feature = "testing-csp")]
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

use crate::common::result::TestResult;

#[cfg(feature = "testing-csp")]
pub(crate) const CREATE_TEST_FRAME_START: Urn<'static> =
	tightbeam::urn!("tightbeam", "event:job/create-test-frame-start");
#[cfg(feature = "testing-csp")]
pub(crate) const CREATE_TEST_FRAME_SUCCESS: Urn<'static> =
	tightbeam::urn!("tightbeam", "event:job/create-test-frame-success");
#[cfg(feature = "testing-csp")]
pub(crate) const TRANSFORM_CONTENT_START: Urn<'static> =
	tightbeam::urn!("tightbeam", "event:job/transform-content-start");
#[cfg(feature = "testing-csp")]
pub(crate) const TRANSFORM_CONTENT_SUCCESS: Urn<'static> =
	tightbeam::urn!("tightbeam", "event:job/transform-content-success");
#[cfg(feature = "testing-csp")]
pub(crate) const VALIDATE_FRAME_START: Urn<'static> = tightbeam::urn!("tightbeam", "event:job/validate-frame-start");
#[cfg(feature = "testing-csp")]
pub(crate) const VALIDATE_FRAME_SUCCESS: Urn<'static> =
	tightbeam::urn!("tightbeam", "event:job/validate-frame-success");

// The `job!` items implement `Job` over tuple-destructured parameters. A `Job`
// input must be an owned type, with no borrow.
job! {
	/// Creates a test frame with the given content.
	name: CreateTestFrame,
	fn run((id, content): (String, String)) -> Result<Frame, TightBeamError> {
		compose! {
			V0: id: id.as_bytes(),
				message: TestMessage { content }
		}
	}
}

job! {
	/// Passes the frame through unchanged, as the validation step of the tests.
	name: ValidateFrame,
	fn run((frame,): (Frame,)) -> Result<Frame, TightBeamError> {
		Ok(frame)
	}
}

job! {
	/// Appends "_transformed" to the content of the frame.
	name: TransformContent,
	fn run((frame,): (Frame,)) -> Result<Frame, TightBeamError> {
		let msg: TestMessage = frame.decode_message()?;
		compose! {
			V0: id: frame.metadata().id(),
				message: TestMessage {
					content: format!("{}_transformed", msg.content)
				}
		}
	}
}

// The test of a pipeline over plain results

/// The three `job!` items chain over plain results in order, so the last job
/// transforms the frame that the first job created. Method syntax on a
/// `Result` reaches the inherent `Result::and_then`, so this test holds the
/// chain of the jobs, and the unit tests of `Pipeline` hold
/// `Pipeline::and_then`.
#[test]
fn three_job_items_chain_over_plain_results() -> TestResult {
	let created = CreateTestFrame::run(("test-001".to_string(), "content".to_string()));
	let validated = created.and_then(|f| ValidateFrame::run((f,)));
	let transformed = validated.and_then(|f| TransformContent::run((f,)));
	let frame = transformed.run()?;

	let message: TestMessage = frame.decode_message()?;
	assert_eq!(message, TestMessage::sample(Some("content_transformed")));
	Ok(())
}

// L1: the assertion spec of the URN events that the job steps emit

#[cfg(feature = "testing-csp")]
tb_assert_spec! {
	pub AutoTraceSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			// Each `then_job` step emits the URNs of its job
			// (`urn:tightbeam:event:job/...`).
			(CREATE_TEST_FRAME_START, exactly!(1)),
			(CREATE_TEST_FRAME_SUCCESS, exactly!(1)),
			(VALIDATE_FRAME_START, exactly!(1)),
			(VALIDATE_FRAME_SUCCESS, exactly!(1)),
			(TRANSFORM_CONTENT_START, exactly!(1)),
			(TRANSFORM_CONTENT_SUCCESS, exactly!(1))
		]
	}
}

// L2: the CSP process spec of the valid state transitions

#[cfg(feature = "testing-csp")]
tb_process_spec! {
	pub PipelineProcess,
	events {
		observable {
			CREATE_TEST_FRAME_START,
			CREATE_TEST_FRAME_SUCCESS,
			VALIDATE_FRAME_START,
			VALIDATE_FRAME_SUCCESS,
			TRANSFORM_CONTENT_START,
			TRANSFORM_CONTENT_SUCCESS
		}
		hidden { }
	}
	states {
		Idle => { CREATE_TEST_FRAME_START => Creating },
		Creating => { CREATE_TEST_FRAME_SUCCESS => Validating },
		Validating => { VALIDATE_FRAME_START => ValidatingRun },
		ValidatingRun => { VALIDATE_FRAME_SUCCESS => Transforming },
		Transforming => { TRANSFORM_CONTENT_START => TransformingRun },
		TransformingRun => { TRANSFORM_CONTENT_SUCCESS => Done }
	}
	terminal { Done }
}

#[cfg(feature = "testing-csp")]
tb_scenario! {
	name: test_pipeline_auto_trace_urns,
	config: ScenarioConfig::builder()
		.with_spec(AutoTraceSpec::latest())
		.with_csp(PipelineProcess)
		.build(),
	environment Pipeline {
		exec: |pipeline| {
			pipeline
				.start(("test-001".to_string(), "content".to_string()))
				.then_job::<CreateTestFrame, _>()
				.map(|f| (f,))
				.then_job::<ValidateFrame, _>()
				.map(|f| (f,))
				.then_job::<TransformContent, _>()
				.run()
		}
	}
}
