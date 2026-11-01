//! The reading of a trace with no gate decision.
//!
//! Nothing in the harness takes a gate, so a scenario records no decision.
//! These tests hold the two halves of that: a spec may not require a decision
//! that the run never reaches, and a run with no decision reads as accepted.

use tightbeam::testing::{Expect, Layer, ScenarioConfig};
use tightbeam::trace::{ConsumedTrace, ExecutionMode};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario};

const STEP: Urn<'static> = tightbeam::urn!("test", "event:gate/step");

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

/// A run that ends in `Ok` and records no gate decision reads as accepted.
#[test]
fn a_run_with_no_gate_decision_reads_as_accepted() {
	let trace = ConsumedTrace::new();
	assert_eq!(ExecutionMode::of(&Ok(()), &trace), ExecutionMode::Accept);
}

// Layer 1 must reject this: the run takes no gate, so `gate: Ok` names a
// decision that the run never reaches.
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
