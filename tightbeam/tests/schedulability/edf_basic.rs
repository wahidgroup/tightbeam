//! EDF schedulability integration tests

use core::time::Duration;

use tightbeam::builder::TypeBuilder;
use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::ScenarioConf;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario, wcet};

// Define a real-time process with EDF scheduling
tb_process_spec! {
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
			"task1" => wcet!(Duration::from_millis(3)),
			"task2" => wcet!(Duration::from_millis(5)),
			"task3" => wcet!(Duration::from_millis(2))
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
tb_assert_spec! {
	pub EdfAssertSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("task1", exactly!(1)),
			("task2", exactly!(1)),
			("task3", exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_edf_with_fdr,
	config: ScenarioConf::<()>::builder()
		.with_spec(EdfAssertSpec::latest())
		.with_fdr(FdrConfig {
			seeds: 2,
			max_depth: 8,
			max_internal_run: 4,
			timeout_ms: 500,
			specs: vec![EdfSchedulableProcess::process()],
			fail_fast: true,
			expect_failure: false,
			..Default::default()
		})
		.build(),
	environment Bare {
		exec: |trace| {
			trace.event("task1")?;
			trace.event("task2")?;
			trace.event("task3")?;
			Ok(())
		}
	}
}
