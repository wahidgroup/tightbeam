//! A scenario that names a CSP model and FDR specs, graded through the public
//! API of tightbeam alone.
//!
//! The model answers deadlock and divergence freedom over every seed, and the
//! specs grade the recorded trace.

use tightbeam::tb_cases;
use tightbeam::testing::fdr::{Decision, FdrConfig};
use tightbeam::testing::specs::csp::{Event, Process, ProcessBuildError, State};
use tightbeam::testing::ScenarioConfig;
use tightbeam::trace::{ConsumedTrace, TraceCollector};
use tightbeam::TightBeamError;

use crate::common::csp::once;
use crate::common::result::TestResult;
use crate::fdr::spinning;

/// A run that the spec of each scenario performs.
const ONE_GO: &[Event] = &[Event("go")];

/// A run past the end of the spec of each scenario.
const TWO_GOES: &[Event] = &[Event("go"), Event("go")];

/// What a scenario decides: the deadlock freedom and the divergence freedom of
/// its model, and the trace refinement of its run.
type Decided = (Decision, Decision, Decision);

/// A process that takes `go` once and stops at its accepting `Done`, which is
/// the spec of each scenario and the sound model.
fn going() -> Process {
	once("Going", ("Ready", "Done"), "go")
}

/// A model whose accepting `Idle` offers `go`, which leads to `Stuck`, a state
/// that can neither terminate nor act.
fn stuck_after_go() -> Process {
	let built: Result<Process, ProcessBuildError> = Process::builder("StuckAfterGo")
		.initial_state(State("Idle"))
		.add_observable(Event("go"))
		.add_transition(State("Idle"), Event("go"), State("Stuck"))
		.add_terminal(State("Idle"))
		.build();

	built.expect("a model of one event builds")
}

/// The trace of a run that records each event of `run` in order.
fn recorded(run: &[Event]) -> Result<ConsumedTrace, TightBeamError> {
	let collector = TraceCollector::new();
	for event in run {
		collector.event(*event)?;
	}

	let mut trace = ConsumedTrace::new();
	trace.populate_from_collector(&collector);
	Ok(trace)
}

// The model of a scenario with specs answers deadlock freedom and divergence
// freedom, and its spec grades the recorded run. A row with a defect refutes
// one decision and holds the other two.
tb_cases! {
	fn a_scenario_with_specs_decides_its_model_and_its_run(
		(model, run, decided): (fn() -> Process, &'static [Event], Decided)
	) -> TestResult {
		let fdr = FdrConfig { specs: vec![going()], ..Default::default() };
		let config = ScenarioConfig::builder().with_csp(model()).with_fdr(fdr).build()?;
		let trace = recorded(run)?;

		let verdict = config.verify(&trace, Ok(()))?;
		let layer3 = verdict.fdr().map(|fdr| (fdr.deadlock_free, fdr.divergence_free, fdr.trace_refines));
		assert_eq!(layer3, Some(decided));
		Ok(())
	}
	cases {
		/// A sound model and a run of the spec hold each decision.
		a_sound_model_and_a_run_of_its_spec => (going, ONE_GO, (Decision::Holds, Decision::Holds, Decision::Holds)),
		/// `go` leads from `Idle` to `Stuck`, so the model deadlocks.
		a_model_that_deadlocks => (stuck_after_go, ONE_GO, (Decision::Refuted, Decision::Holds, Decision::Holds)),
		/// The hidden cycle after `a` diverges.
		a_model_that_diverges => (spinning, ONE_GO, (Decision::Holds, Decision::Refuted, Decision::Holds)),
		/// The spec stops after its one `go`, so a second `go` leaves it.
		a_run_past_the_end_of_its_spec => (going, TWO_GOES, (Decision::Holds, Decision::Holds, Decision::Refuted)),
	}
}
