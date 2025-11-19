//! WCET constraint integration tests
//!
//! NOTE: These tests use instrumentation which relies on global state.
//! When running tests in parallel, a test guard serializes instrumentation operations
//! to prevent interference. However, for maximum reliability, these tests should
//! be run with `--test-threads=1` or `RUST_TEST_THREADS=1` to ensure complete isolation.

#![cfg(all(feature = "testing-timing", feature = "testing-fdr", feature = "instrument"))]

use std::time::Duration;

use tightbeam::builder::TypeBuilder;
use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::macros::InstrumentationMode;
use tightbeam::testing::specs::csp::Process;

tightbeam::tb_process_spec! {
	pub SimpleWcetProcess,
	events {
		observable { "process" }
		hidden { }
	}
	states {
		S0 => { "process" => S1 }
	}
	terminal { S1 }
	timing {
		wcet: { "process" => tightbeam::wcet!(Duration::from_millis(10)) }
	}
}

tightbeam::tb_assert_spec! {
	pub SimpleWcetSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("process", tightbeam::exactly!(1))
		]
	},
}

/// Helper to build FDR config for timing tests
fn build_timing_fdr_config(specs: Vec<Process>) -> FdrConfig {
	FdrConfig {
		seeds: 2,
		max_depth: 8,
		max_internal_run: 4,
		timeout_ms: 500,
		specs,
		fail_fast: true,
		expect_failure: false,
		scheduler_count: None,
		process_count: None,
		scheduler_model: None,
		fault_model: None,
		fmea: None,
	}
}

// Test 1: WCET constraint satisfied (within limit)
// This test verifies that:
// 1. Timing constraints are properly defined on the process
// 2. Instrumentation events are captured correctly
// 3. Timing verification can be run and passes for durations within constraint
// Note: This test focuses on verifying the infrastructure works correctly.
// The actual timing verification would be called during FDR exploration or in hooks.
tightbeam::tb_scenario! {
	name: test_wcet_constraint_passing,
	spec: SimpleWcetSpec,
	fdr: build_timing_fdr_config(vec![SimpleWcetProcess::process()]),
	instrumentation: InstrumentationMode::Custom {
		enable_payloads: false,
		enable_internal_detail: false,
		sample_enabled_sets: false,
		sample_refusals: false,
		divergence_heuristics: false,
		record_durations: true,
		max_events: 1024,
	},
	environment Bare {
		exec: |trace| {
			// Emit timing event with duration within WCET constraint (5ms < 10ms)
			tightbeam::tb_instrument!(
				TimingWcet,
				label = "process",
				duration_ns = 5_000_000 // 5ms in nanoseconds
			);
			trace.event("process");
			Ok(())
		}
	},
	hooks {
		on_pass: |trace| {
			// Verify timing constraints exist on process
			let process = SimpleWcetProcess::process();
			let constraints = process.timing_constraints.as_ref().expect("Process should have timing constraints");

			// Verify timing constraints against trace
			let timing_result = constraints.verify_with_process(trace, Some(&process))
				.expect("Timing verification should succeed");

			// Verify no violations (within constraint: 5ms < 10ms)
			assert!(timing_result.passed, "Timing verification should pass for duration within constraint. Violations: {:?}", timing_result.wcet_violations);
			assert!(timing_result.wcet_violations.is_empty(), "No WCET violations expected");
		},
	}
}

// Test 2: WCET constraint boundary case (exactly at limit)
// Tests that durations exactly equal to the constraint are acceptable
tightbeam::tb_scenario! {
	name: test_wcet_constraint_at_limit,
	spec: SimpleWcetSpec,
	fdr: build_timing_fdr_config(vec![SimpleWcetProcess::process()]),
	instrumentation: InstrumentationMode::Custom {
		enable_payloads: false,
		enable_internal_detail: false,
		sample_enabled_sets: false,
		sample_refusals: false,
		divergence_heuristics: false,
		record_durations: true,
		max_events: 1024,
	},
	environment Bare {
		exec: |trace| {
			// Emit timing event with duration exactly at WCET constraint (10ms == 10ms)
			tightbeam::tb_instrument!(
				TimingWcet,
				label = "process",
				duration_ns = 10_000_000 // 10ms in nanoseconds - at the limit
			);
			trace.event("process");
			Ok(())
		}
	},
	hooks {
		on_pass: |trace| {
			// Verify timing constraints exist on process
			let process = SimpleWcetProcess::process();
			let constraints = process.timing_constraints.as_ref().expect("Process should have timing constraints");

			// Verify timing constraints against trace
			let timing_result = constraints.verify_with_process(trace, Some(&process))
				.expect("Timing verification should succeed");

			// Verify no violations (at limit: 10ms == 10ms, should pass)
			assert!(timing_result.passed, "Timing verification should pass for duration at constraint limit");
			assert!(timing_result.wcet_violations.is_empty(), "No WCET violations expected at limit");
		},
	}
}

// Test 3: WCET constraint violation (exceeds limit)
// This test verifies that timing violations are properly detected when
// observed durations exceed the WCET constraint.
tightbeam::tb_scenario! {
	name: test_wcet_constraint_violation,
	spec: SimpleWcetSpec,
	fdr: build_timing_fdr_config(vec![SimpleWcetProcess::process()]),
	instrumentation: InstrumentationMode::Custom {
		enable_payloads: false,
		enable_internal_detail: false,
		sample_enabled_sets: false,
		sample_refusals: false,
		divergence_heuristics: false,
		record_durations: true,
		max_events: 1024,
	},
	environment Bare {
		exec: |trace| {
			// Emit timing event with duration exceeding WCET constraint (15ms > 10ms)
			tightbeam::tb_instrument!(
				TimingWcet,
				label = "process",
				duration_ns = 15_000_000 // 15ms in nanoseconds - violates 10ms constraint
			);
			trace.event("process");
			Ok(())
		}
	},
	hooks {
		on_pass: |trace| {
			// Verify timing constraints exist on process
			let process = SimpleWcetProcess::process();
			let constraints = process.timing_constraints.as_ref().expect("Process should have timing constraints");

			// Verify timing constraints against trace
			let timing_result = constraints.verify_with_process(trace, Some(&process))
				.expect("Timing verification should succeed");

			// Verify violations detected (exceeds constraint: 15ms > 10ms)
			assert!(!timing_result.passed, "Timing verification should fail for duration exceeding constraint. Result: {timing_result:?}");
			assert!(!timing_result.wcet_violations.is_empty(), "WCET violations should be detected");
			assert_eq!(timing_result.wcet_violations.len(), 1, "Exactly one WCET violation expected");

			// Verify violation details
			let violation = &timing_result.wcet_violations[0];
			assert_eq!(violation.event.0, "process");
			assert_eq!(violation.wcet_ns, 10_000_000); // 10ms constraint
			assert_eq!(violation.observed_ns, 15_000_000); // 15ms observed
		},
	}
}
