//! RMA schedulability integration tests

use core::time::Duration;

use tightbeam::builder::TypeBuilder;
use tightbeam::testing::error::TestingError;
use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::specs::csp::Event;
use tightbeam::testing::{ScenarioConfig, SetupEnv, TestHooks};
use tightbeam::utils::urn::Urn;
use tightbeam::{exactly, wcet, TightBeamError};
use tightbeam::{tb_assert_spec, tb_process_spec, tb_scenario};

pub(crate) const TASK1: Urn<'static> = Urn::new("test", "event:rma-basic/task1");
pub(crate) const TASK2: Urn<'static> = Urn::new("test", "event:rma-basic/task2");

// Define a real-time process with timing and schedulability constraints
tb_process_spec! {
	pub RmaSchedulableProcess,
	events {
		observable { TASK1, TASK2 }
		hidden { }
	}
	states {
		S0 => { TASK1 => S1 },
		S1 => { TASK2 => S2 }
	}
	terminal { S2 }
	timing {
		wcet: {
			TASK1 => wcet!(Duration::from_millis(3)),
			TASK2 => wcet!(Duration::from_millis(5))
		}
	}
	schedulability {
		scheduler: RateMonotonic,
		periods: {
			TASK1 => Duration::from_millis(10),
			TASK2 => Duration::from_millis(20)
		}
	}
}

// RMA schedulable task set integration test with FDR
// Utilization: 3/10 + 5/20 = 0.3 + 0.25 = 0.55
// RMA bound for n=2: 2*(2^(1/2) - 1) ≈ 0.828
// 0.55 < 0.828, so schedulable
tb_assert_spec! {
	pub RmaAssertSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(TASK1, exactly!(1)),
			(TASK2, exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_rma_with_fdr,
	config: ScenarioConfig::builder()
		.with_spec(RmaAssertSpec::latest())
		.with_csp(RmaSchedulableProcess)
		.with_fdr(FdrConfig {
			seeds: 2,
			max_depth: 8,
			max_internal_run: 4,
			timeout_ms: 500,
			specs: vec![RmaSchedulableProcess::process()],
			fail_fast: true,
			expect_failure: false,
			..Default::default()
		})
		.with_hooks(TestHooks {
			on_pass: Some(std::sync::Arc::new(|result| {
				assert!(result.assert_spec.is_some(), "Assert spec should be present");
				assert!(result.process.is_some(), "Process should be present");

				let constraints = result
					.timing_constraints
					.as_ref()
					.ok_or(TightBeamError::TestingError(TestingError::InvalidTimingConstraint))?;
				assert!(constraints.has_constraint(&Event::from(TASK1)), "Should have task1 constraint");
				assert!(constraints.has_constraint(&Event::from(TASK2)), "Should have task2 constraint");
				Ok(())
			})),
			on_fail: None,
		})
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(TASK1)?;
			trace.event(TASK2)?;
			Ok(())
		}
	}
}
