//! A scenario that names a CSP model and FDR specs, graded through the public
//! API of tightbeam alone.
//!
//! The model answers deadlock and divergence freedom over every seed, and the
//! specs grade the recorded trace.

use tightbeam::testing::fdr::{Decision, FdrConfig};
use tightbeam::testing::specs::csp::{Event, Process, ProcessBuildError, State};
use tightbeam::testing::ScenarioConfig;
use tightbeam::trace::ConsumedTrace;

/// A model whose accepting `Idle` offers `go`, which leads to `Stuck`, a state
/// that can neither terminate nor act.
fn stuck_after_go() -> Result<Process, ProcessBuildError> {
	Process::builder("StuckAfterGo")
		.initial_state(State("Idle"))
		.add_observable(Event("go"))
		.add_transition(State("Idle"), Event("go"), State("Stuck"))
		.add_terminal(State("Idle"))
		.build()
}

/// A spec that offers `go` at `Ready` and stops at `Done`.
fn going() -> Result<Process, ProcessBuildError> {
	Process::builder("Going")
		.initial_state(State("Ready"))
		.add_observable(Event("go"))
		.add_transition(State("Ready"), Event("go"), State("Done"))
		.add_terminal(State("Done"))
		.build()
}

#[test]
fn a_scenario_with_specs_explores_its_model_for_deadlock() -> Result<(), Box<dyn std::error::Error>> {
	let fdr = FdrConfig { specs: vec![going()?], ..Default::default() };
	let config = ScenarioConfig::builder().with_csp(stuck_after_go()?).with_fdr(fdr).build()?;

	let verdict = config.verify(&ConsumedTrace::new(), Ok(()))?;
	let decided = verdict.fdr().map(|fdr| fdr.deadlock_free);
	assert_eq!(decided, Some(Decision::Refuted), "`go` leads from `Idle` to `Stuck`");
	Ok(())
}
