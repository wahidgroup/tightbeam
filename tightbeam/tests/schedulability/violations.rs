//! The tests of schedulability violations.

use core::error::Error;
use core::time::Duration;

use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::specs::csp::{Process, ProcessBuildError};
use tightbeam::testing::{Expect, Layer, ScenarioConfig, SetupEnv, TBSpec};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario, wcet};

pub(crate) const TASK1: Urn<'static> = tightbeam::urn!("test", "event:violations/task1");
pub(crate) const TASK2: Urn<'static> = tightbeam::urn!("test", "event:violations/task2");

// Every scenario in this file releases TASK1 once. Only the two-task
// processes release TASK2, so the shared contract names TASK1 alone.
tb_assert_spec! {
	pub SchedulabilityViolationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(TASK1, exactly!(1))
		]
	}
}

// The task set of this process misses a deadline under RMA, and its
// utilization sits under the bound of EDF, so Layer 3 must run the analysis of
// RMA to catch the miss.
tb_process_spec! {
	pub RmaNotSchedulableProcess,
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
			TASK1 => wcet!(Duration::from_millis(6)),
			TASK2 => wcet!(Duration::from_millis(5))
		}
	}
	schedulability {
		scheduler: RateMonotonic,
		periods: {
			TASK1 => Duration::from_millis(10),
			TASK2 => Duration::from_millis(15)
		}
	}
}

/// The configuration that grades [`SchedulabilityViolationSpec`], analyses the
/// task set of `process`, and expects `expect`.
fn schedule_config(
	process: Result<Process, ProcessBuildError>,
	expect: Expect,
) -> Result<ScenarioConfig, Box<dyn Error>> {
	let fdr = FdrConfig {
		seeds: 1,
		max_depth: 10,
		max_internal_run: 5,
		timeout_ms: 1000,
		specs: vec![process?],
		fail_fast: false,
		..Default::default()
	};

	let builder = ScenarioConfig::builder().with_spec(SchedulabilityViolationSpec::latest());
	let builder = builder.with_fdr(fdr);
	Ok(builder.with_expect(expect).build()?)
}

/// The configuration of [`schedule_config`] that expects Layer 3 to refuse the
/// task set of `process`.
fn violation_config(process: Result<Process, ProcessBuildError>) -> Result<ScenarioConfig, Box<dyn Error>> {
	schedule_config(process, Expect::Violation(Layer::Refinement))
}

// The RMA task set runs at utilization 0.933 against a bound of about 0.828,
// so response-time analysis decides it: TASK2 responds at 17 ms, past its
// deadline of 15 ms. `Process::schedulability_violated` reports the miss and
// Layer 3 rejects the run. The expectation is what grades that rejection.
tb_scenario! {
	name: test_rma_schedulability_violation_detected,
	config: violation_config(RmaNotSchedulableProcess::process()),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(TASK1)?;
			trace.event(TASK2)?;
			Ok(())
		}
	}
}

// The task set of the RMA process above, under EDF.
tb_process_spec! {
	pub EdfSchedulableProcess,
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
			TASK1 => wcet!(Duration::from_millis(6)),
			TASK2 => wcet!(Duration::from_millis(5))
		}
	}
	schedulability {
		scheduler: EarliestDeadlineFirst,
		periods: {
			TASK1 => Duration::from_millis(10),
			TASK2 => Duration::from_millis(15)
		}
	}
}

// The utilization of 0.933 sits under the bound of EDF, 1.0, so Layer 3
// accepts under EDF the task set that it refuses under RMA.
tb_scenario! {
	name: edf_admits_the_task_set_that_rma_refuses,
	config: schedule_config(EdfSchedulableProcess::process(), Expect::Pass),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(TASK1)?;
			trace.event(TASK2)?;
			Ok(())
		}
	}
}

// The task set of this process exceeds the utilization bound of EDF.
tb_process_spec! {
	pub EdfNotSchedulableProcess,
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
			TASK1 => wcet!(Duration::from_millis(8)),
			TASK2 => wcet!(Duration::from_millis(5))
		}
	}
	schedulability {
		scheduler: EarliestDeadlineFirst,
		periods: {
			TASK1 => Duration::from_millis(10),
			TASK2 => Duration::from_millis(20)
		}
	}
}

// The EDF task set runs at utilization 1.05 against a bound of 1.0, so Layer 3
// rejects the run for the same reason under the other scheduler.
tb_scenario! {
	name: test_edf_schedulability_violation_detected,
	config: violation_config(EdfNotSchedulableProcess::process()),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(TASK1)?;
			trace.event(TASK2)?;
			Ok(())
		}
	}
}

// This process names a period for TASK1 and no `timing` block, so its task
// set has no WCET.
tb_process_spec! {
	pub ProcessWithoutTiming,
	events {
		observable { TASK1 }
		hidden { }
	}
	states {
		S0 => { TASK1 => S1 }
	}
	terminal { S1 }
	schedulability {
		scheduler: RateMonotonic,
		periods: {
			TASK1 => Duration::from_millis(10)
		}
	}
}

// A period without a WCET leaves the task set unanalysable. Layer 3 reports a
// miss, because an unanalysable task set is not shown to meet its deadlines.
tb_scenario! {
	name: test_missing_wcet_for_period_detected,
	config: violation_config(ProcessWithoutTiming::process()),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(TASK1)?;
			Ok(())
		}
	}
}

/// An empty task set: the spec key under test is the block, not the analysis.
fn schedule_only_task_set() -> tightbeam::testing::schedulability::TaskSet {
	tightbeam::testing::schedulability::TaskSet {
		tasks: vec![],
		scheduler: tightbeam::testing::schedulability::SchedulerType::RateMonotonic,
	}
}

tb_assert_spec! {
	pub ScheduleOnlySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [],
		schedulability: {
			task_set: schedule_only_task_set(),
			scheduler: RateMonotonic,
			must_be_schedulable: true,
		}
	}
}

/// The block is the only thing this spec names, so a spec that can reject is
/// the observable form of the block reaching the built spec.
#[test]
fn a_schedulability_block_reaches_the_built_spec() {
	assert!(TBSpec::can_reject(ScheduleOnlySpec::latest()));
}
