//! What a trace with no gate decision is read as
//!
//! Nothing in the harness takes a gate, so a scenario records no decision.
//! These tests hold the two halves of that: a spec may not require a decision
//! that was never reached, and the absence of one is not read as a failure.

use tightbeam::testing::{Expect, Layer, ScenarioConfig};
use tightbeam::trace::{ConsumedTrace, ExecutionMode};
use tightbeam::utils::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario};

const STEP: Urn<'static> = Urn::new("test", "event:gate/step");

tb_assert_spec! {
	pub GatelessSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [ (STEP, exactly!(1)) ]
	},
}

tb_assert_spec! {
	pub RequiresGateOkSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [ (STEP, exactly!(1)) ]
	},
}

tb_scenario! {
	name: a_spec_that_requires_no_gate_accepts_a_gateless_run,
	config: ScenarioConfig::builder().with_spec(GatelessSpec::latest()).build(),
	environment Bare {
		exec: |tightbeam::testing::SetupEnv { trace, .. }| {
			trace.event(STEP)?;
			Ok(())
		}
	}
}

#[test]
fn gateless_trace_is_mode_accept() {
	let trace = ConsumedTrace::new();

	assert_eq!(trace.execution_mode(), ExecutionMode::Accept);
}

// Layer 1 must reject this: the run takes no gate, so `gate: Ok` names a
// decision that was never reached. Restoring an unconditional gate write makes
// Layer 1 accept, and the declared expectation then goes unmet.
tb_scenario! {
	name: gate_ok_without_a_gate_is_rejected,
	config: ScenarioConfig::builder()
		.with_spec(RequiresGateOkSpec::latest())
		.with_expect(Expect::Violation(Layer::Assertion))
		.build(),
	environment Bare {
		exec: |tightbeam::testing::SetupEnv { trace, .. }| {
			trace.event(STEP)?;
			Ok(())
		}
	}
}
