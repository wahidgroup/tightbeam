//! EDF schedulability integration tests

use core::time::Duration;

use tightbeam::builder::TypeBuilder;

// Define a real-time process with EDF scheduling
tightbeam::tb_process_spec! {
	pub EdfSchedulableProcess,
	events {
		observable { "task1", "task2", "task3" }
		hidden { }
	}
	states {
		S0 => { "task1" => S1 },
		S1 => { "task2" => S2 },
		S2 => { "task3" => S3 }
	}
	terminal { S3 }
	timing {
		wcet: {
			"task1" => tightbeam::wcet!(Duration::from_millis(3)),
			"task2" => tightbeam::wcet!(Duration::from_millis(5)),
			"task3" => tightbeam::wcet!(Duration::from_millis(2))
		}
	}
	schedulability {
		scheduler: EarliestDeadlineFirst,
		periods: {
			"task1" => Duration::from_millis(10),
			"task2" => Duration::from_millis(20),
			"task3" => Duration::from_millis(30)
		}
	}
}

// EDF schedulable task set integration test with FDR
// Utilization: 3/10 + 5/20 + 2/30 = 0.3 + 0.25 + 0.067 = 0.617
// EDF bound: 1.0
// 0.617 < 1.0, so schedulable
tightbeam::tb_assert_spec! {
	pub EdfAssertSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("task1", tightbeam::exactly!(1)),
			("task2", tightbeam::exactly!(1)),
			("task3", tightbeam::exactly!(1))
		]
	}
}

tightbeam::tb_scenario! {
	name: test_edf_with_fdr,
	spec: EdfAssertSpec,
	fdr: FdrConfig {
		seeds: 2,
		max_depth: 8,
		max_internal_run: 4,
		timeout_ms: 500,
		specs: vec![EdfSchedulableProcess::process()],
		fail_fast: true,
		expect_failure: false,
		scheduler_count: None,
		process_count: None,
		scheduler_model: None,
		fault_model: None,
	},
	environment Bare {
		exec: |trace| {
			trace.event("task1")?;
			trace.event("task2")?;
			trace.event("task3")?;
			Ok(())
		}
	}
}
