//! Schedulability violation tests

use core::time::Duration;

use tightbeam::builder::TypeBuilder;
use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::{Expect, Layer, ScenarioConfig, SetupEnv};
use tightbeam::utils::urn::Urn;
use tightbeam::{tb_assert_spec, tb_process_spec, tb_scenario, wcet};

pub(crate) const TASK1: Urn<'static> = Urn::new("test", "event:violations/task1");
pub(crate) const TASK2: Urn<'static> = Urn::new("test", "event:violations/task2");

// Minimal spec for violation tests
tb_assert_spec! {
	pub SchedulabilityViolationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: []
	}
}

// Define a process that is NOT schedulable under RMA
// This should be caught during FDR exploration
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
			TASK1 => wcet!(Duration::from_millis(8)),
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

// The RMA task set runs at utilization 1.05 against a bound of about 0.828,
// so `Process::schedulability_violated` reports a miss and Layer 3 rejects the
// run. The expectation is what grades that rejection.
tb_scenario! {
	name: test_rma_schedulability_violation_detected,
	config: ScenarioConfig::builder()
		.with_spec(SchedulabilityViolationSpec::latest())
		.with_fdr(FdrConfig {
			seeds: 1,
			max_depth: 10,
			max_internal_run: 5,
			timeout_ms: 1000,
			specs: vec![RmaNotSchedulableProcess::process()],
			fail_fast: false,
			..Default::default()
		})
		.with_expect(Expect::Violation(Layer::Refinement))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(TASK1)?;
			trace.event(TASK2)?;
			Ok(())
		}
	}
}

// Define a process with EDF that exceeds utilization bound
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
	config: ScenarioConfig::builder()
		.with_spec(SchedulabilityViolationSpec::latest())
		.with_fdr(FdrConfig {
			seeds: 1,
			max_depth: 10,
			max_internal_run: 5,
			timeout_ms: 1000,
			specs: vec![EdfNotSchedulableProcess::process()],
			fail_fast: false,
			..Default::default()
		})
		.with_expect(Expect::Violation(Layer::Refinement))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(TASK1)?;
			trace.event(TASK2)?;
			Ok(())
		}
	}
}

// Test process without timing constraints (should handle gracefully)
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

// A period without a WCET leaves the task set unanalysable, which Layer 3
// reports as a miss, because a task set that cannot be analysed has not been
// shown to meet its deadlines.
tb_scenario! {
	name: test_missing_wcet_for_period_detected,
	config: ScenarioConfig::builder()
		.with_spec(SchedulabilityViolationSpec::latest())
		.with_fdr(FdrConfig {
			seeds: 1,
			max_depth: 10,
			max_internal_run: 5,
			timeout_ms: 1000,
			specs: vec![ProcessWithoutTiming::process()],
			fail_fast: false,
			..Default::default()
		})
		.with_expect(Expect::Violation(Layer::Refinement))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(TASK1)?;
			Ok(())
		}
	}
}
