//! Schedulability violation tests

use core::time::Duration;

use tightbeam::builder::TypeBuilder;
use tightbeam::testing::schedulability::SchedulerType;
use tightbeam::testing::SpecViolation;

// Minimal spec for violation tests
tightbeam::tb_assert_spec! {
	pub SchedulabilityViolationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: []
	}
}

// Define a process that is NOT schedulable under RMA
// This should be caught during FDR exploration
tightbeam::tb_process_spec! {
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
			"task1" => tightbeam::wcet!(Duration::from_millis(8)),
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

// Test: RMA schedulability violation should be caught during FDR setup
// This test EXPECTS failure and verifies it's the right kind of failure
tightbeam::tb_scenario! {
	name: test_rma_schedulability_violation_detected,
	spec: SchedulabilityViolationSpec,
	fdr: tightbeam::testing::fdr::FdrConfig {
		seeds: 1,
		max_depth: 10,
		max_internal_run: 5,
		timeout_ms: 1000,
		specs: vec![RmaNotSchedulableProcess::process()],
		fail_fast: false,
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
			Ok(())
		}
	},
	hooks {
		on_fail: |_trace, result| {
			// Verify that we got a schedulability violation with structured data
			let violation = result.spec_violation.as_ref().unwrap_or_else(|| panic!("Expected spec violation"));
			match violation {
				SpecViolation::SchedulabilityViolation(scheduler_result) => {
					// Verify scheduler type
					assert_eq!(scheduler_result.scheduler, SchedulerType::RateMonotonic, "Unexpected scheduler");
					// Verify utilization exceeds bound
					assert!(scheduler_result.utilization > scheduler_result.utilization_bound, "Utilization {} should exceed bound {}", scheduler_result.utilization, scheduler_result.utilization_bound);
					// Verify we have violation details
					assert!(!scheduler_result.violations.is_empty(), "Should have violation details");

					Ok(())
				},
				SpecViolation::SchedulabilityError(_) => {
					// Also acceptable if it's a schedulability error
					Ok(())
				},
				_ => {
					Err(format!("Expected SchedulabilityViolation, got: {violation:?}").into())
				}
			}
		}
	}
}

// Define a process with EDF that exceeds utilization bound
tightbeam::tb_process_spec! {
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
			"task1" => tightbeam::wcet!(Duration::from_millis(8)),
			"task2" => tightbeam::wcet!(Duration::from_millis(5))
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
tightbeam::tb_scenario! {
	name: test_edf_schedulability_violation_detected,
	spec: SchedulabilityViolationSpec,
	fdr: tightbeam::testing::fdr::FdrConfig {
		seeds: 1,
		max_depth: 10,
		max_internal_run: 5,
		timeout_ms: 1000,
		specs: vec![EdfNotSchedulableProcess::process()],
		fail_fast: false,
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
			Ok(())
		}
	},
	hooks {
		on_fail: |_trace, result| {
			// Verify that we got a schedulability violation with structured data
			let violation = result.spec_violation.as_ref().unwrap_or_else(|| panic!("Expected spec violation"));
			match violation {
				SpecViolation::SchedulabilityViolation(scheduler_result) => {
					// Verify scheduler type
					assert_eq!(scheduler_result.scheduler, SchedulerType::EarliestDeadlineFirst, "Unexpected scheduler");
					// Verify utilization exceeds bound
					assert!(scheduler_result.utilization > scheduler_result.utilization_bound, "Utilization {} should exceed bound {}", scheduler_result.utilization, scheduler_result.utilization_bound);
					// EDF bound should be 1.0
					assert_eq!(scheduler_result.utilization_bound, 1.0, "EDF utilization bound should be 1.0");
					// Verify we have violation details
					assert!(!scheduler_result.violations.is_empty(), "Should have violation details");

					Ok(())
				},
				SpecViolation::SchedulabilityError(_) => {
					// Also acceptable if it's a schedulability error
					Ok(())
				},
				_ => {
					Err(format!("Expected SchedulabilityViolation, got: {violation:?}").into())
				}
			}
		}
	}
}

// Test process without timing constraints (should handle gracefully)
tightbeam::tb_process_spec! {
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
tightbeam::tb_scenario! {
	name: test_missing_wcet_for_period_detected,
	spec: SchedulabilityViolationSpec,
	fdr: tightbeam::testing::fdr::FdrConfig {
		seeds: 1,
		max_depth: 10,
		max_internal_run: 5,
		timeout_ms: 1000,
		specs: vec![ProcessWithoutTiming::process()],
		fail_fast: false,
		expect_failure: false,
		scheduler_count: None,
		process_count: None,
		scheduler_model: None,
		fault_model: None,
	},
	environment Bare {
		exec: |trace| {
			trace.event("task1")?;
			Ok(())
		}
	},
	hooks {
		on_fail: |_trace, result| {
			// Should fail with schedulability error for missing WCET
			let violation = result.spec_violation.as_ref().unwrap_or_else(|| panic!("Expected spec violation"));
			match violation {
				SpecViolation::SchedulabilityError(error) => {
					// Verify it's a valid error with details
					let error_display = format!("{error}");
					assert!(!error_display.is_empty(), "Should have error details: {error:?}");
					Ok(())
				},
				_ => {
					Err(format!("Expected SchedulabilityError, got: {violation:?}").into())
				}
			}
		}
	}
}
