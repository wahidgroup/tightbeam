//! RMA schedulability integration tests

use core::time::Duration;

use tightbeam::builder::TypeBuilder;
use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::specs::csp::Event;
use tightbeam::testing::{ScenarioConf, TestHooks};
use tightbeam::{exactly, wcet};
use tightbeam::{tb_assert_spec, tb_process_spec, tb_scenario};

// Define a real-time process with timing and schedulability constraints
tb_process_spec! {
	pub RmaSchedulableProcess,
	events {
		observable { "task1", "task2" }
		hidden { }
	}
	states {
		S0 => { "task1" => S1 },
		S1 => { "task2" => S2 }
	}
	terminal { S2 }
	timing {
		wcet: {
			"task1" => wcet!(Duration::from_millis(3)),
			"task2" => wcet!(Duration::from_millis(5))
		}
	}
	schedulability {
		scheduler: RateMonotonic,
		periods: {
			"task1" => Duration::from_millis(10),
			"task2" => Duration::from_millis(20)
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
		gate: Accepted,
		assertions: [
			("task1", exactly!(1)),
			("task2", exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_rma_with_fdr,
	config: ScenarioConf::<()>::builder()
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

				let constraints = result.timing_constraints.as_ref().expect("Timing constraints should be present");
				assert!(constraints.has_constraint(&Event("task1")), "Should have task1 constraint");
				assert!(constraints.has_constraint(&Event("task2")), "Should have task2 constraint");
				Ok(())
			})),
			on_fail: None,
		})
		.build(),
	environment Bare {
		exec: |trace| {
			trace.event("task1")?;
			trace.event("task2")?;
			Ok(())
		}
	}
}
