//! Schedulability violation tests

use core::time::Duration;
use std::sync::Arc;

use tightbeam::builder::TypeBuilder;
use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::schedulability::SchedulerType;
use tightbeam::testing::{ScenarioConf, SpecViolation, TestHooks};
use tightbeam::{tb_assert_spec, tb_process_spec, tb_scenario, wcet};

// Minimal spec for violation tests
tb_assert_spec! {
	pub SchedulabilityViolationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: []
	}
}

// Define a process that is NOT schedulable under RMA
// This should be caught during FDR exploration
tb_process_spec! {
	pub RmaNotSchedulableProcess,
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
			"task1" => wcet!(Duration::from_millis(8)),
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

// Test: RMA schedulability violation should be caught during FDR setup
// This test EXPECTS failure and verifies it's the right kind of failure
tb_scenario! {
	name: test_rma_schedulability_violation_detected,
	config: ScenarioConf::<()>::builder()
		.with_spec(SchedulabilityViolationSpec::latest())
		.with_fdr(FdrConfig {
			seeds: 1,
			max_depth: 10,
			max_internal_run: 5,
			timeout_ms: 1000,
			specs: vec![RmaNotSchedulableProcess::process()],
			fail_fast: false,
			expect_failure: false,
			..Default::default()
		})
		.with_hooks(TestHooks {
			on_pass: None,
			on_fail: Some(Arc::new(|_result, violation| {
				match violation {
				SpecViolation::SchedulabilityViolation(scheduler_result) => {
					assert_eq!(scheduler_result.scheduler, SchedulerType::RateMonotonic, "Unexpected scheduler");
					assert!(scheduler_result.utilization > scheduler_result.utilization_bound, "Utilization {} should exceed bound {}", scheduler_result.utilization, scheduler_result.utilization_bound);
					assert!(!scheduler_result.violations.is_empty(), "Should have violation details");
					Ok(())
				},
				SpecViolation::SchedulabilityError(_) => Ok(()),
				_ => panic!("Expected SchedulabilityViolation, got: {violation:?}")
			}
		})),
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

// Define a process with EDF that exceeds utilization bound
tb_process_spec! {
	pub EdfNotSchedulableProcess,
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
			"task1" => wcet!(Duration::from_millis(8)),
			"task2" => wcet!(Duration::from_millis(5))
		}
	}
	schedulability {
		scheduler: EarliestDeadlineFirst,
		periods: {
			"task1" => Duration::from_millis(10),
			"task2" => Duration::from_millis(20)
		}
	}
}

// Test: EDF schedulability violation should be caught during FDR setup
tb_scenario! {
	name: test_edf_schedulability_violation_detected,
	config: ScenarioConf::<()>::builder()
		.with_spec(SchedulabilityViolationSpec::latest())
		.with_fdr(FdrConfig {
			seeds: 1,
			max_depth: 10,
			max_internal_run: 5,
			timeout_ms: 1000,
			specs: vec![EdfNotSchedulableProcess::process()],
			fail_fast: false,
			expect_failure: false,
			..Default::default()
		})
		.with_hooks(TestHooks {
			on_pass: None,
			on_fail: Some(Arc::new(|_result, violation| {
				match violation {
					SpecViolation::SchedulabilityViolation(scheduler_result) => {
						assert_eq!(scheduler_result.scheduler, SchedulerType::EarliestDeadlineFirst, "Unexpected scheduler");
						assert!(scheduler_result.utilization > scheduler_result.utilization_bound, "Utilization {} should exceed bound {}", scheduler_result.utilization, scheduler_result.utilization_bound);
						assert_eq!(scheduler_result.utilization_bound, 1.0, "EDF utilization bound should be 1.0");
						assert!(!scheduler_result.violations.is_empty(), "Should have violation details");
						Ok(())
					},
					SpecViolation::SchedulabilityError(_) => Ok(()),
					_ => panic!("Expected SchedulabilityViolation, got: {violation:?}")
				}
			})),
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

// Test process without timing constraints (should handle gracefully)
tb_process_spec! {
	pub ProcessWithoutTiming,
	events {
		observable { "task1" }
		hidden { }
	}
	states {
		S0 => { "task1" => S1 }
	}
	terminal { S1 }
	schedulability {
		scheduler: RateMonotonic,
		periods: {
			"task1" => Duration::from_millis(10)
		}
	}
}

// Test: Process with periods but no timing constraints should be caught
tb_scenario! {
	name: test_missing_wcet_for_period_detected,
	config: ScenarioConf::<()>::builder()
		.with_spec(SchedulabilityViolationSpec::latest())
		.with_fdr(FdrConfig {
			seeds: 1,
			max_depth: 10,
			max_internal_run: 5,
			timeout_ms: 1000,
			specs: vec![ProcessWithoutTiming::process()],
			fail_fast: false,
			expect_failure: false,
			..Default::default()
		})
		.with_hooks(TestHooks {
			on_pass: None,
			on_fail: Some(Arc::new(|_result, violation| {
				match violation {
					SpecViolation::SchedulabilityError(error) => {
						let error_display = format!("{error}");
						assert!(!error_display.is_empty(), "Should have error details: {error:?}");
						Ok(())
					},
					_ => panic!("Expected SchedulabilityError, got: {violation:?}")
				}
			})),
		})
		.build(),
	environment Bare {
		exec: |trace| {
			trace.event("task1")?;
			Ok(())
		}
	}
}
