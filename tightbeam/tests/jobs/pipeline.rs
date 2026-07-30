//! Integration tests for job pipeline orchestration with tb_scenario!
//!
//! Tests demonstrate:
//! - Auto-emitted URN trace events from PipelineBuilder
//! - CSP process specification for state machine validation
//! - L1 assertion specs for event cardinality

#![cfg(all(feature = "testing", feature = "std"))]

use tightbeam::der::Sequence;
use tightbeam::utils::task::Pipeline;
use tightbeam::utils::urn::Urn;
use tightbeam::{compose, exactly, job, tb_assert_spec, tb_scenario, testing::SetupEnv};
use tightbeam::{Beamable, Frame, TightBeamError};

#[cfg(feature = "testing-csp")]
use tightbeam::tb_process_spec;
#[cfg(feature = "testing-csp")]
use tightbeam::testing::ScenarioConfig;

pub(crate) const FALLBACK_TRIGGERED: Urn<'static> = Urn::new("test", "event:pipeline/fallback-triggered");
pub(crate) const PIPELINE_COMPLETE: Urn<'static> = Urn::new("test", "event:pipeline/pipeline-complete");
pub(crate) const PIPELINE_START: Urn<'static> = Urn::new("test", "event:pipeline/pipeline-start");

#[cfg(feature = "testing-csp")]
pub(crate) const CREATE_TEST_FRAME_START: Urn<'static> = Urn::new("tightbeam", "event:job/create-test-frame-start");
#[cfg(feature = "testing-csp")]
pub(crate) const CREATE_TEST_FRAME_SUCCESS: Urn<'static> = Urn::new("tightbeam", "event:job/create-test-frame-success");
#[cfg(feature = "testing-csp")]
pub(crate) const TRANSFORM_CONTENT_START: Urn<'static> = Urn::new("tightbeam", "event:job/transform-content-start");
#[cfg(feature = "testing-csp")]
pub(crate) const TRANSFORM_CONTENT_SUCCESS: Urn<'static> = Urn::new("tightbeam", "event:job/transform-content-success");
#[cfg(feature = "testing-csp")]
pub(crate) const VALIDATE_FRAME_START: Urn<'static> = Urn::new("tightbeam", "event:job/validate-frame-start");
#[cfg(feature = "testing-csp")]
pub(crate) const VALIDATE_FRAME_SUCCESS: Urn<'static> = Urn::new("tightbeam", "event:job/validate-frame-success");

// Test message types
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
struct TestMessage {
	content: String,
}

// Test jobs using tuple-destructured parameters (implements Job trait)
// Note: Job trait Input type must be owned (no borrowed types)
job! {
	/// Creates a test frame with given content.
	name: CreateTestFrame,
	fn run((id, content): (String, String)) -> Result<Frame, TightBeamError> {
		compose! {
			V0: id: id.as_bytes(),
				message: TestMessage { content }
		}
	}
}

job! {
	/// Validates a frame (passthrough for testing).
	name: ValidateFrame,
	fn run((frame,): (Frame,)) -> Result<Frame, TightBeamError> {
		Ok(frame)
	}
}

job! {
	/// Transforms frame content by appending "_transformed".
	name: TransformContent,
	fn run((frame,): (Frame,)) -> Result<Frame, TightBeamError> {
		let msg: TestMessage = tightbeam::decode(&frame.message)?;

		compose! {
			V0: id: &frame.metadata.id,
				message: TestMessage {
					content: format!("{}_transformed", msg.content)
				}
		}
	}
}

// ============================================================================
// L1: Assertion Specification - Manual Events
// ============================================================================

tb_assert_spec! {
	pub ManualEventSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PIPELINE_START, exactly!(1)),
			(PIPELINE_COMPLETE, exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_pipeline_manual_events,
	spec: ManualEventSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(PIPELINE_START)?;

			// Direct Result pipeline (no PipelineBuilder = no auto-trace)
			let _frame = CreateTestFrame::run(("test-001".to_string(), "content".to_string()))
				.and_then(|f| ValidateFrame::run((f,)))
				.and_then(|f| TransformContent::run((f,)))
				.run()?;

			trace.event(PIPELINE_COMPLETE)?;
			Ok(())
		}
	}
}

// ============================================================================
// L1: Assertion Specification - Auto URN Events from PipelineBuilder
// ============================================================================

#[cfg(feature = "testing-csp")]
tb_assert_spec! {
	pub AutoTraceSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			// Auto-emitted job URNs from PipelineBuilder (urn:tightbeam:event:job/...)
			(CREATE_TEST_FRAME_START, exactly!(1)),
			(CREATE_TEST_FRAME_SUCCESS, exactly!(1)),
			(VALIDATE_FRAME_START, exactly!(1)),
			(VALIDATE_FRAME_SUCCESS, exactly!(1)),
			(TRANSFORM_CONTENT_START, exactly!(1)),
			(TRANSFORM_CONTENT_SUCCESS, exactly!(1))
		]
	}
}

// ============================================================================
// L2: CSP Process Specification - Valid State Transitions
// ============================================================================

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
				.and_then(CreateTestFrame::run)
				.map(|f| (f,))
				.and_then(ValidateFrame::run)
				.map(|f| (f,))
				.and_then(TransformContent::run)
				.run()
		}
	}
}

// ============================================================================
// Fallback Pipeline Test
// ============================================================================

tb_assert_spec! {
	pub FallbackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(FALLBACK_TRIGGERED, exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_pipeline_with_fallback,
	spec: FallbackSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Pipeline with fallback on error
			let failing: Result<Frame, TightBeamError> = Err(TightBeamError::InvalidOrder);
			let _frame = failing.or_else(|_| {
				trace.event(FALLBACK_TRIGGERED)?;
				compose! {
					V0: id: b"fallback",
						message: TestMessage {
							content: "fallback_content".to_string()
						}
				}
			}).run()?;

			Ok(())
		}
	}
}
