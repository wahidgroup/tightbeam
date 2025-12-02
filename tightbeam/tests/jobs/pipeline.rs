//! Integration tests for job pipeline orchestration with tb_scenario!

#![cfg(all(feature = "testing", feature = "std"))]

use tightbeam::der::Sequence;
use tightbeam::testing::ScenarioConf;
use tightbeam::utils::task::{Pipeline, PipelineBuilder};
use tightbeam::{compose, exactly, job, tb_assert_spec, tb_scenario};
use tightbeam::{Beamable, Frame, TightBeamError};

// Test message types
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
struct TestMessage {
	content: String,
}

// Test jobs for integration testing
job! {
	name: CreateTestFrame,
	fn run(id: &str, content: &str) -> Result<Frame, TightBeamError> {
		compose! {
			V0: id: id.as_bytes(),
				message: TestMessage {
					content: content.to_string()
				}
		}
	}
}

job! {
	name: ValidateFrame,
	fn run(frame: Frame) -> Result<Frame, TightBeamError> {
		Ok(frame)
	}
}

job! {
	name: TransformContent,
	fn run(frame: Frame) -> Result<Frame, TightBeamError> {
		let msg: TestMessage = tightbeam::decode(&frame.message)?;

		compose! {
			V0: id: frame.metadata.id.clone(),
				message: TestMessage {
					content: format!("{}_transformed", msg.content)
				}
		}
	}
}

// Integration tests with tb_scenario!
tb_assert_spec! {
	pub PipelineSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("pipeline_start", exactly!(1)),
			("pipeline_complete", exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_pipeline_with_trace,
	config: ScenarioConf::<()>::builder()
		.with_spec(PipelineSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| {
			trace.event("pipeline_start")?;

			// Use pipeline with trace context
			let _frame = PipelineBuilder::new(trace.clone())
				.start("test-001")
				.and_then(|id| CreateTestFrame::run(id, "content"))
				.and_then(ValidateFrame::run)
				.and_then(TransformContent::run)
				.run()?;

			trace.event("pipeline_complete")?;
			Ok(())
		}
	}
}

tb_scenario! {
	name: test_pipeline_with_fallback_trace,
	config: ScenarioConf::<()>::builder()
		.with_spec(PipelineSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| {
			trace.event("pipeline_start")?;

			// Pipeline with fallback
			let failing: Result<Frame, TightBeamError> = Err(TightBeamError::InvalidOrder);

			let _frame = failing.or_else(|_| {
				compose! {
					V0: id: b"fallback",
						message: TestMessage {
							content: "fallback_content".to_string()
						}
				}
			}).run()?;

			trace.event("pipeline_complete")?;
			Ok(())
		}
	}
}
