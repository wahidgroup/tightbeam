//! EDF schedulability integration tests

use core::time::Duration;

use tightbeam::builder::TypeBuilder;
use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::utils::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario, wcet};

pub(crate) const TASK1: Urn<'static> = Urn::new("test", "event:edf-basic/task1");
pub(crate) const TASK2: Urn<'static> = Urn::new("test", "event:edf-basic/task2");
pub(crate) const TASK3: Urn<'static> = Urn::new("test", "event:edf-basic/task3");

// Define a real-time process with EDF scheduling
tb_process_spec! {
	pub EdfSchedulableProcess,
	events {
		observable { TASK1, TASK2, TASK3 }
		hidden { }
	}
	states {
		S0 => { TASK1 => S1 },
		S1 => { TASK2 => S2 },
		S2 => { TASK3 => S3 }
	}
	terminal { S3 }
	timing {
		wcet: {
			TASK1 => wcet!(Duration::from_millis(3)),
			TASK2 => wcet!(Duration::from_millis(5)),
			TASK3 => wcet!(Duration::from_millis(2))
		}
	}
	schedulability {
		scheduler: EarliestDeadlineFirst,
		periods: {
			TASK1 => Duration::from_millis(10),
			TASK2 => Duration::from_millis(20),
			TASK3 => Duration::from_millis(30)
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
		gate: Ok,
		assertions: [
			(TASK1, exactly!(1)),
			(TASK2, exactly!(1)),
			(TASK3, exactly!(1))
		]
	}
}

tb_scenario! {
	name: test_edf_with_fdr,
	config: ScenarioConfig::builder()
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
		exec: |SetupEnv { trace, .. }| {
			trace.event(TASK1)?;
			trace.event(TASK2)?;
			trace.event(TASK3)?;
			Ok(())
		}
	}
}
