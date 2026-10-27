//! The integration tests of WCET constraints.

#![cfg(all(feature = "testing-timing", feature = "testing-fdr", feature = "instrument"))]

use core::error::Error;
use std::time::Duration;

use tightbeam::instrumentation::TbInstrumentationConfig;
use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::specs::csp::Process;
use tightbeam::testing::{HookContext, ScenarioConfig, SetupEnv, TestHooks};
use tightbeam::trace::TraceConfig;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario, wcet};

use tightbeam::urn::Urn;

pub(crate) const PROCESS: Urn<'static> = tightbeam::urn!("test", "event:wcet/process");

tb_process_spec! {
	pub SimpleWcetProcess,
	events {
		observable { PROCESS }
		hidden { }
	}
	states {
		S0 => { PROCESS => S1 }
	}
	terminal { S1 }
	timing {
		wcet: { PROCESS => wcet!(Duration::from_millis(10)) }
	}
}

tb_assert_spec! {
	pub SimpleWcetSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(PROCESS, exactly!(1))
		]
	},
}

/// The FDR configuration of the timing tests, with `specs` as its specs.
fn build_timing_fdr_config(specs: impl IntoIterator<Item = Process>) -> FdrConfig {
	let specs: Vec<Process> = specs.into_iter().collect();
	FdrConfig {
		seeds: 2,
		max_depth: 8,
		max_internal_run: 4,
		timeout_ms: 500,
		specs,
		fail_fast: true,
		..Default::default()
	}
}

/// The configuration of a WCET scenario, which records each duration, and
/// whose pass hook runs `check` with the process of [`SimpleWcetProcess`].
fn wcet_config(
	check: impl Fn(&HookContext, &Process) + Send + Sync + 'static,
) -> Result<ScenarioConfig, Box<dyn Error>> {
	let process = SimpleWcetProcess::process()?;
	let fdr = build_timing_fdr_config(vec![process.clone()]);
	let trace = TraceConfig::with_instrumentation(TbInstrumentationConfig {
		enable_payloads: false,
		enable_internal_detail: false,
		sample_enabled_sets: false,
		sample_refusals: false,
		divergence_heuristics: false,
		record_durations: true,
		max_events: 1024,
	});

	let hooks = TestHooks::on_pass(move |context| check(context, &process));
	let builder = ScenarioConfig::builder().with_spec(SimpleWcetSpec::latest()).with_fdr(fdr);
	Ok(builder.with_trace(trace.into()).with_hooks(hooks).build()?)
}

// Test 1: a duration within the WCET passes. The test checks that:
// 1. The process declares its timing constraints.
// 2. The trace records the instrumentation events.
// 3. Timing verification runs and passes a duration within the constraint.
// FDR exploration or a hook calls the timing verification, and this test
// calls it from its pass hook to check the timing infrastructure.
tb_scenario! {
	name: test_wcet_constraint_passing,
	config: wcet_config(|context, process| {
				let constraints = process
					.timing_constraints
					.as_ref()
					.expect("the spec under test declares WCET constraints");

				let timing_result = constraints
					.verify_with_process(context.trace(), Some(process))
					.expect("verifying a declared constraint against the recorded trace");
				// 5 ms sits within the 10 ms WCET, so the check passes.
				assert!(timing_result.passed, "Timing verification should pass for duration within constraint. Violations: {:?}", timing_result.wcet_violations);
				assert!(timing_result.wcet_violations.is_empty(), "No WCET violations expected");
			}),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// The event takes 5 ms, within the 10 ms WCET.
			trace.event(PROCESS)?.with_timing(Duration::from_nanos(5_000_000));
			Ok(())
		}
	}
}

// Test 2: a duration equal to the WCET satisfies the constraint, because the
// bound is inclusive.
tb_scenario! {
	name: test_wcet_constraint_at_limit,
	config: wcet_config(|context, process| {
				let constraints = process
					.timing_constraints
					.as_ref()
					.expect("the spec under test declares WCET constraints");

				let timing_result = constraints
					.verify_with_process(context.trace(), Some(process))
					.expect("verifying a declared constraint against the recorded trace");
				// 10 ms equals the 10 ms WCET, so the check passes.
				assert!(timing_result.passed, "Timing verification should pass for duration at constraint limit");
				assert!(timing_result.wcet_violations.is_empty(), "No WCET violations expected at limit");
			}),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(PROCESS)?.with_timing(Duration::from_nanos(10_000_000));
			Ok(())
		}
	}
}

// Test 3: a duration past the WCET violates the constraint, so the timing
// check reports one violation with the observed duration.
tb_scenario! {
	name: test_wcet_constraint_violation,
	config: wcet_config(|context, process| {
				let constraints = process
					.timing_constraints
					.as_ref()
					.expect("the spec under test declares WCET constraints");

				let timing_result = constraints
					.verify_with_process(context.trace(), Some(process))
					.expect("verifying a declared constraint against the recorded trace");
				assert!(!timing_result.passed, "Timing verification should fail for duration exceeding constraint. Result: {timing_result:?}");
				assert!(!timing_result.wcet_violations.is_empty(), "WCET violations should be detected");
				assert_eq!(timing_result.wcet_violations.len(), 1, "Exactly one WCET violation expected");

				let violation = &timing_result.wcet_violations[0];
				assert_eq!(violation.event.0, PROCESS.to_string());
				assert_eq!(violation.wcet_ns, 10_000_000);
				assert_eq!(violation.observed_ns, 15_000_000);
			}),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			trace.event(PROCESS)?.with_timing(Duration::from_nanos(15_000_000));
			Ok(())
		}
	}
}
