//! WCET constraint integration tests

#![cfg(all(feature = "testing-timing", feature = "testing-fdr", feature = "instrument"))]

use std::sync::Arc;
use std::time::Duration;

use tightbeam::builder::TypeBuilder;
use tightbeam::instrumentation::TbInstrumentationConfig;
use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::specs::csp::Process;
use tightbeam::testing::{ScenarioConf, TestHooks};
use tightbeam::trace::TraceConfig;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario, wcet};

tb_process_spec! {
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
		wcet: { "process" => wcet!(Duration::from_millis(10)) }
	}
}

tb_assert_spec! {
	pub SimpleWcetSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("process", exactly!(1))
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
		..Default::default()
	}
}

// Test 1: WCET constraint satisfied (within limit)
// This test verifies that:
// 1. Timing constraints are properly defined on the process
// 2. Instrumentation events are captured correctly
// 3. Timing verification can be run and passes for durations within constraint
// Note: This test focuses on verifying the infrastructure works correctly.
// The actual timing verification would be called during FDR exploration or in hooks.
tb_scenario! {
	name: test_wcet_constraint_passing,
	config: ScenarioConf::<()>::builder()
		.with_spec(SimpleWcetSpec::latest())
		.with_fdr(build_timing_fdr_config(vec![SimpleWcetProcess::process()]))
		.with_trace(TraceConfig::with_instrumentation(TbInstrumentationConfig {
			enable_payloads: false,
			enable_internal_detail: false,
			sample_enabled_sets: false,
			sample_refusals: false,
			divergence_heuristics: false,
			record_durations: true,
			max_events: 1024,
		}).into())
		.with_hooks(TestHooks {
			on_pass: Some(Arc::new(|result| {
				// Verify timing constraints exist on process
				let process = SimpleWcetProcess::process();
				let constraints = process.timing_constraints.as_ref().expect("Process should have timing constraints");

				// Verify timing constraints against trace
				let timing_result = constraints.verify_with_process(&result.trace, Some(&process))?;

				// Verify no violations (within constraint: 5ms < 10ms)
				assert!(timing_result.passed, "Timing verification should pass for duration within constraint. Violations: {:?}", timing_result.wcet_violations);
				assert!(timing_result.wcet_violations.is_empty(), "No WCET violations expected");
				Ok(())
			})),
			on_fail: None,
		})
		.build(),
	environment Bare {
		exec: |trace| {
			// Emit timing event with duration within WCET constraint (5ms < 10ms)
			trace.event("process")?.with_timing(Duration::from_nanos(5_000_000));
			Ok(())
		}
	}
}

// Test 2: WCET constraint boundary case (exactly at limit)
// Tests that durations exactly equal to the constraint are acceptable
tb_scenario! {
	name: test_wcet_constraint_at_limit,
	config: ScenarioConf::<()>::builder()
		.with_spec(SimpleWcetSpec::latest())
		.with_fdr(build_timing_fdr_config(vec![SimpleWcetProcess::process()]))
		.with_trace(TraceConfig::with_instrumentation(TbInstrumentationConfig {
			enable_payloads: false,
			enable_internal_detail: false,
			sample_enabled_sets: false,
			sample_refusals: false,
			divergence_heuristics: false,
			record_durations: true,
			max_events: 1024,
		}).into())
		.with_hooks(TestHooks {
			on_pass: Some(Arc::new(|result| {
				// Verify timing constraints exist on process
				let process = SimpleWcetProcess::process();
				let constraints = process.timing_constraints.as_ref().expect("Process should have timing constraints");

				// Verify timing constraints against trace
				let timing_result = constraints.verify_with_process(&result.trace, Some(&process))?;

				// Verify no violations (at limit: 10ms == 10ms, should pass)
				assert!(timing_result.passed, "Timing verification should pass for duration at constraint limit");
				assert!(timing_result.wcet_violations.is_empty(), "No WCET violations expected at limit");
				Ok(())
			})),
			on_fail: None,
		})
		.build(),
	environment Bare {
		exec: |trace| {
			trace.event("process")?.with_timing(Duration::from_nanos(10_000_000));
			Ok(())
		}
	}
}

// Test 3: WCET constraint violation (exceeds limit)
// This test verifies that timing violations are properly detected when
// observed durations exceed the WCET constraint.
tb_scenario! {
	name: test_wcet_constraint_violation,
	config: ScenarioConf::<()>::builder()
		.with_spec(SimpleWcetSpec::latest())
		.with_fdr(build_timing_fdr_config(vec![SimpleWcetProcess::process()]))
		.with_trace(TraceConfig::with_instrumentation(TbInstrumentationConfig {
			enable_payloads: false,
			enable_internal_detail: false,
			sample_enabled_sets: false,
			sample_refusals: false,
			divergence_heuristics: false,
			record_durations: true,
			max_events: 1024,
		}).into())
		.with_hooks(TestHooks {
			on_pass: Some(Arc::new(|result| {
				let process = SimpleWcetProcess::process();
				let constraints = process.timing_constraints.as_ref().expect("Process should have timing constraints");
				let timing_result = constraints.verify_with_process(&result.trace, Some(&process))?;
				assert!(!timing_result.passed, "Timing verification should fail for duration exceeding constraint. Result: {timing_result:?}");
				assert!(!timing_result.wcet_violations.is_empty(), "WCET violations should be detected");
				assert_eq!(timing_result.wcet_violations.len(), 1, "Exactly one WCET violation expected");
				let violation = &timing_result.wcet_violations[0];
				assert_eq!(violation.event.0, "process");
				assert_eq!(violation.wcet_ns, 10_000_000);
				assert_eq!(violation.observed_ns, 15_000_000);
				Ok(())
			})),
			on_fail: None,
		})
		.build(),
	environment Bare {
		exec: |trace| {
			trace.event("process")?.with_timing(Duration::from_nanos(15_000_000));
			Ok(())
		}
	}
}
