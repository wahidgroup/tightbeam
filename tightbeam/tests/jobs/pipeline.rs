//! Integration tests for job pipeline orchestration with tb_scenario!
//!
//! Tests demonstrate:
//! - Auto-emitted URN trace events from PipelineBuilder
//! - CSP process specification for state machine validation
//! - L1 assertion specs for event cardinality

#![cfg(all(feature = "testing", feature = "std"))]

use tightbeam::der::Sequence;
use tightbeam::utils::task::Pipeline;
use tightbeam::{compose, exactly, job, tb_assert_spec, tb_scenario, testing::SetupEnv};
use tightbeam::{Beamable, Frame, TightBeamError};

#[cfg(feature = "testing-csp")]
use tightbeam::tb_process_spec;
#[cfg(feature = "testing-csp")]
use tightbeam::testing::ScenarioConf;

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
			V0: id: frame.metadata.id.clone(),
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
			(pipeline_start, exactly!(1)),
			(pipeline_complete, exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_pipeline_manual_events,
	spec: ManualEventSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(ManualEventSpec::pipeline_start)?;

			// Direct Result pipeline (no PipelineBuilder = no auto-trace)
			let _frame = CreateTestFrame::run(("test-001".to_string(), "content".to_string()))
				.and_then(|f| ValidateFrame::run((f,)))
				.and_then(|f| TransformContent::run((f,)))
				.run()?;

			trace.event(ManualEventSpec::pipeline_complete)?;
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
			// Shorthand labels match full URNs: "foo" matches "urn:*:instrumentation:event/foo"
			(create_test_frame_start, exactly!(1)),
			(create_test_frame_success, exactly!(1)),
			(validate_frame_start, exactly!(1)),
			(validate_frame_success, exactly!(1)),
			(transform_content_start, exactly!(1)),
			(transform_content_success, exactly!(1))
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
			"create_test_frame_start",
			"create_test_frame_success",
			"validate_frame_start",
			"validate_frame_success",
			"transform_content_start",
			"transform_content_success"
		}
		hidden {}
	}
	states {
		Idle => { "create_test_frame_start" => Creating },
		Creating => { "create_test_frame_success" => Validating },
		Validating => { "validate_frame_start" => ValidatingRun },
		ValidatingRun => { "validate_frame_success" => Transforming },
		Transforming => { "transform_content_start" => TransformingRun },
		TransformingRun => { "transform_content_success" => Done }
	}
	terminal { Done }
}

#[cfg(feature = "testing-csp")]
tb_scenario! {
	name: test_pipeline_auto_trace_urns,
	config: ScenarioConf::builder()
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
			(fallback_triggered, exactly!(1))
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
				trace.event(FallbackSpec::fallback_triggered)?;
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
