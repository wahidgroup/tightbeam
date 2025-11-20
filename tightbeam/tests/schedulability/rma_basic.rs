//! RMA schedulability integration tests

use core::time::Duration;

use tightbeam::builder::TypeBuilder;

// Define a real-time process with timing and schedulability constraints
tightbeam::tb_process_spec! {
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
			"task1" => tightbeam::wcet!(Duration::from_millis(3)),
			"task2" => tightbeam::wcet!(Duration::from_millis(5))
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
tightbeam::tb_assert_spec! {
	pub RmaAssertSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("task1", tightbeam::exactly!(1)),
			("task2", tightbeam::exactly!(1))
		]
	}
}

tightbeam::tb_scenario! {
	name: test_rma_with_fdr,
	spec: RmaAssertSpec,
	csp: RmaSchedulableProcess,
	fdr: FdrConfig {
		seeds: 2,
		max_depth: 8,
		max_internal_run: 4,
		timeout_ms: 500,
		specs: vec![RmaSchedulableProcess::process()],
		fail_fast: true,
		expect_failure: false,
		scheduler_count: None,
		process_count: None,
		scheduler_model: None,
		fault_model: None,
		fmea: None,
	},
	environment Bare {
		exec: |trace| {
			trace.event("task1");
			trace.event("task2");
			Ok(())
		}
	},
	hooks {
		on_pass: |_trace, result| {
			// Verify that ScenarioResult contains the specification data (owned for export)
			assert!(result.assert_spec.is_some(), "Assert spec should be present");
			assert!(result.process.is_some(), "Process should be present");
			assert!(result.timing_constraints.is_some(), "Timing constraints should be present");

			// Verify we can access the process data
			let process = result.process.as_ref().unwrap();
			assert_eq!(process.name, "RmaSchedulableProcess", "Process name should match");

			// Verify timing constraints are accessible
			let constraints = result.timing_constraints.as_ref().unwrap();
			assert!(constraints.has_constraint(&tightbeam::testing::specs::csp::Event("task1")));
			assert!(constraints.has_constraint(&tightbeam::testing::specs::csp::Event("task2")));

			// Task set and schedulability result would be populated if schedulability analysis was performed
			// (These are set by FDR timing subsystem during exploration)

			Ok(())
		},
	}
}
